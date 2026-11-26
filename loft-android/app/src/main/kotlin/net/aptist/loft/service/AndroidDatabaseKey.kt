package net.aptist.loft.service

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.DataInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.NoSuchFileException
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.attribute.BasicFileAttributes
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import java.security.SecureRandom
import java.security.UnrecoverableKeyException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal enum class StorageKeyFailure { UNAVAILABLE, RECOVERY_REQUIRED }

internal class StorageKeyException(val failure: StorageKeyFailure) : Exception(failure.name)

/** Used serially by the private :vpn command worker. The wrapping key stays in Android Keystore. */
internal class AndroidDatabaseKey(private val directory: File, private val alias: String) {

    fun <T : AutoCloseable> open(openDatabase: (String, ByteArray, Boolean) -> T): T {
        // Some Android app-data paths use a directory alias. Resolve it once
        // before creating files, and keep database/envelope leaves unresolved.
        val paths = platform { StoragePaths(directory.canonicalFile) }
        val provision = platform { loadOrProvision(paths) }
        try {
            val core = openDatabase(paths.database.path, provision.key, provision.allowCreate)
            if (provision.allowCreate) {
                // Once a core can accept writes, loss of its database is a recovery
                // failure. Seal that decision before exposing the core to callers.
                try { platform { writeEnvelope(paths, provision.wrappingKey, provision.key, ACTIVE) } }
                catch (failure: StorageKeyException) {
                    runCatching { core.close() }
                    throw failure
                }
            }
            return core
        } finally { provision.key.fill(0) }
    }

    private fun loadOrProvision(paths: StoragePaths): Provision {
        val directory = paths.directory
        val database = paths.database
        Files.createDirectories(directory.toPath())
        val parent = requireNotNull(directory.parentFile)
        syncDirectory(parent)
        // Android can create noBackupFilesDir on first access. Persist its
        // app-data directory entry before accepting the first storage write.
        syncDirectory(requireNotNull(parent.parentFile))
        // A prior rename may have succeeded before its final directory sync
        // failed. Re-establish durability before trusting the visible phase.
        syncDirectory(directory)
        val databaseInfo = attributes(database)
        if (databaseInfo != null && !databaseInfo.isRegularFile) recoveryRequired()
        val hasSidecar = listOf("-journal", "-wal", "-shm").any {
            attributes(File(directory, database.name + it)) != null
        }
        if (databaseInfo == null && hasSidecar) recoveryRequired()

        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val wrapped = readEnvelope(paths.envelope)
        val existingKey = keyStore.getKey(alias, null)
        if (existingKey != null && existingKey !is SecretKey) recoveryRequired()
        val wrappingKey = existingKey

        if (wrapped == null) {
            // A key-only orphan is possible if the process dies before its first
            // atomic commit. Database files always require an authenticated envelope.
            if (databaseInfo != null) recoveryRequired()
            val key = wrappingKey ?: generateWrappingKey()
            val secret = ByteArray(KEY_BYTES)
            try {
                SecureRandom().nextBytes(secret)
                writeEnvelope(paths, key, secret, PROVISIONING)
                return Provision(secret, key, allowCreate = true)
            } catch (failure: Exception) {
                secret.fill(0)
                throw failure
            }
        }

        if (wrappingKey == null) recoveryRequired()
        val phase = wrapped[1]
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey, GCMParameterSpec(TAG_BITS, wrapped, HEADER_BYTES, IV_BYTES))
        cipher.updateAAD(associatedData(phase))
        val secret = cipher.doFinal(wrapped, HEADER_BYTES + IV_BYTES, KEY_BYTES + TAG_BYTES)
        val provisioning = phase == PROVISIONING
        if (secret.size != KEY_BYTES || (!provisioning && (databaseInfo == null || databaseInfo.size() == 0L))) {
            secret.fill(0)
            recoveryRequired()
        }
        return Provision(secret, wrappingKey, provisioning)
    }

    private fun readEnvelope(envelope: File): ByteArray? {
        val info = attributes(envelope) ?: return null
        if (!info.isRegularFile || info.size() != ENVELOPE_BYTES.toLong()) recoveryRequired()
        val bytes = ByteArray(ENVELOPE_BYTES)
        DataInputStream(Files.newInputStream(envelope.toPath(), NOFOLLOW_LINKS)).use {
            it.readFully(bytes)
            if (it.read() != -1) recoveryRequired()
        }
        if (bytes[0] != VERSION || (bytes[1] != PROVISIONING && bytes[1] != ACTIVE)) recoveryRequired()
        return bytes
    }

    private fun writeEnvelope(paths: StoragePaths, wrappingKey: SecretKey, secret: ByteArray, phase: Byte) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        // The Android Keystore provider generates a fresh IV for every encryption.
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey)
        val iv = cipher.iv
        check(iv.size == IV_BYTES)
        cipher.updateAAD(associatedData(phase))
        val encrypted = cipher.doFinal(secret)
        check(encrypted.size == KEY_BYTES + TAG_BYTES)

        val temporary = File(paths.directory, "key.wrap.new")
        // A killed writer can leave a staged file. Only the fsynced, atomically
        // renamed envelope is authoritative. Never follow a stale staged symlink.
        Files.deleteIfExists(temporary.toPath())
        check(temporary.createNewFile())
        try {
            FileOutputStream(temporary).use {
                it.write(byteArrayOf(VERSION, phase))
                it.write(iv)
                it.write(encrypted)
                it.fd.sync()
            }
            Files.move(temporary.toPath(), paths.envelope.toPath(), ATOMIC_MOVE, REPLACE_EXISTING)
            syncDirectory(paths.directory)
        } finally { Files.deleteIfExists(temporary.toPath()) }
    }

    private fun generateWrappingKey(): SecretKey =
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build())
        }.generateKey()

    private fun associatedData(phase: Byte): ByteArray =
        byteArrayOf(VERSION, phase) + alias.encodeToByteArray()

    private fun attributes(file: File): BasicFileAttributes? = try {
        Files.readAttributes(file.toPath(), BasicFileAttributes::class.java, NOFOLLOW_LINKS)
    } catch (_: NoSuchFileException) { null }

    private fun syncDirectory(file: File) {
        val descriptor = Os.open(file.path, OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC, 0)
        try {
            if (!OsConstants.S_ISDIR(Os.fstat(descriptor).st_mode)) unavailable()
            Os.fsync(descriptor)
        } finally { Os.close(descriptor) }
    }

    private fun <T> platform(block: () -> T): T = try { block() }
    catch (_: KeyPermanentlyInvalidatedException) { recoveryRequired() }
    catch (_: UnrecoverableKeyException) { recoveryRequired() }
    catch (_: BadPaddingException) { recoveryRequired() }
    catch (_: GeneralSecurityException) { unavailable() }
    catch (_: ProviderException) { unavailable() }
    catch (_: IOException) { unavailable() }
    catch (_: ErrnoException) { unavailable() }
    catch (_: SecurityException) { unavailable() }

    private fun recoveryRequired(): Nothing = throw StorageKeyException(StorageKeyFailure.RECOVERY_REQUIRED)
    private fun unavailable(): Nothing = throw StorageKeyException(StorageKeyFailure.UNAVAILABLE)

    private class Provision(val key: ByteArray, val wrappingKey: SecretKey, val allowCreate: Boolean)

    private class StoragePaths(val directory: File) {
        val database = File(directory, "config.db")
        val envelope = File(directory, "key.wrap")
    }

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val VERSION: Byte = 1
        private const val PROVISIONING: Byte = 1
        private const val ACTIVE: Byte = 2
        private const val HEADER_BYTES = 2
        private const val IV_BYTES = 12
        private const val KEY_BYTES = 32
        private const val TAG_BITS = 128
        private const val TAG_BYTES = TAG_BITS / 8
        private const val ENVELOPE_BYTES = HEADER_BYTES + IV_BYTES + KEY_BYTES + TAG_BYTES
    }
}
