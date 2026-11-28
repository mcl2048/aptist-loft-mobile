#![forbid(unsafe_code)]

use loft_core::{
    CoreError, LoadedLocalConfig, LocalConfigEdit, LocalConfigStore, LocalSettings,
    MAX_NODE_INPUT_BYTES, MAX_NODES, NOTES_IMAGE_LIMIT, PROTECTION_IMAGE_LIMIT, PrivateRecord,
    VAULT_IMAGE_LIMIT,
};
use rusqlite::{
    Connection, Error, ErrorCode, OpenFlags, Row, TransactionBehavior, config::DbConfig,
    limits::Limit, params,
};
use std::{fmt::Write, fs, io, path::Path, time::Duration};
use zeroize::Zeroizing;

const PAGE_BYTES: u64 = 4096;
const MAX_PAGES: i32 = 16_384;
const MAX_SETTINGS_BYTES: usize = 8192;
const APPLICATION_ID: u32 = u32::from_be_bytes(*b"LOFT");
const SCHEMA_VERSION: u32 = 3;
const HUB_SESSION_LIMIT: usize = 8192;

const SCHEMA: &str = "
    CREATE TABLE local_config (
        singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
        generation BLOB NOT NULL CHECK (length(generation) = 8),
        next_node_id BLOB NOT NULL CHECK (length(next_node_id) = 8),
        settings BLOB NOT NULL CHECK (length(settings) BETWEEN 1 AND 8192)
    ) STRICT;
    CREATE TABLE local_nodes (
        id BLOB NOT NULL PRIMARY KEY CHECK (length(id) = 8),
        uri BLOB NOT NULL CHECK (length(uri) BETWEEN 1 AND 524288)
    ) STRICT, WITHOUT ROWID;";
const PRIVATE_SCHEMA: &str = "
    CREATE TABLE local_private (
        kind INTEGER NOT NULL PRIMARY KEY CHECK (kind BETWEEN 1 AND 4),
        data BLOB NOT NULL CHECK (
            length(data) BETWEEN 1 AND CASE kind
                WHEN 1 THEN 245760
                WHEN 2 THEN 8192
                WHEN 3 THEN 2048
                WHEN 4 THEN 491520
            END
        )
    ) STRICT;";

/// One device-local anonymous configuration store. The Android service supplies the
/// private directory path and a random key unwrapped by Keystore for this open only.
pub struct SqlCipherStore {
    connection: Connection,
}

impl SqlCipherStore {
    pub fn open(path: &Path, key: &[u8], allow_create: bool) -> Result<Self, CoreError> {
        if key.len() != 32 || !path.is_absolute() {
            return Err(CoreError::StorageUnavailable);
        }
        check_database_file(path, allow_create)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let flags = if allow_create {
            flags | OpenFlags::SQLITE_OPEN_CREATE
        } else {
            flags
        };
        let mut connection = Connection::open_with_flags(path, flags).map_err(sql_error)?;
        connection
            .busy_timeout(Duration::from_millis(250))
            .map_err(sql_error)?;
        connection
            .set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)
            .map_err(sql_error)?;
        connection
            .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(sql_error)?;
        connection
            .set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)
            .map_err(sql_error)?;
        connection
            .set_limit(
                Limit::SQLITE_LIMIT_LENGTH,
                (MAX_NODE_INPUT_BYTES + MAX_SETTINGS_BYTES) as i32,
            )
            .map_err(sql_error)?;
        set_key(&connection, key)?;

        // Set exclusive locking before the first schema read so another owner cannot
        // load stale settings and write through a second connection. SQLite recovers
        // a hot rollback journal while acquiring this lock.
        let mode: String = pragma(&connection, "locking_mode = EXCLUSIVE")?;
        if mode != "exclusive" {
            return Err(CoreError::StorageUnavailable);
        }
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .map_err(sql_error)?;
        let mode: String = pragma(&transaction, "journal_mode")?;
        if mode != "delete" {
            return Err(CoreError::StorageRecoveryRequired);
        }
        let application: u32 = pragma(&transaction, "application_id")?;
        let version: u32 = pragma(&transaction, "user_version")?;
        let file_page_bytes: String = pragma(&transaction, "cipher_page_size")?;
        let max_pages: i32 = pragma(&transaction, "max_page_count = 16384")?;
        if file_page_bytes.parse::<u64>() != Ok(PAGE_BYTES) || max_pages != MAX_PAGES {
            return Err(CoreError::StorageRecoveryRequired);
        }
        match (application, version) {
            (APPLICATION_ID, SCHEMA_VERSION) => check_cipher_integrity(&transaction)?,
            (APPLICATION_ID, 1 | 2) => {
                check_cipher_integrity(&transaction)?;
                if version == 2 {
                    transaction
                        .execute_batch("ALTER TABLE local_private RENAME TO local_private_v2;")
                        .map_err(sql_error)?;
                }
                transaction
                    .execute_batch(PRIVATE_SCHEMA)
                    .map_err(sql_error)?;
                if version == 2 {
                    transaction
                        .execute_batch(
                            "INSERT INTO local_private SELECT kind, data FROM local_private_v2;
                         DROP TABLE local_private_v2;",
                        )
                        .map_err(sql_error)?;
                }
                transaction
                    .pragma_update(None, "user_version", SCHEMA_VERSION)
                    .map_err(sql_error)?;
            }
            (0, 0) if allow_create => initialize(&transaction)?,
            _ => return Err(CoreError::StorageRecoveryRequired),
        }
        transaction.commit().map_err(sql_error)?;
        Ok(Self { connection })
    }
}

fn check_database_file(path: &Path, allow_create: bool) -> Result<(), CoreError> {
    match fs::symlink_metadata(path) {
        Ok(info)
            if info.is_file()
                && (allow_create || info.len() > 0)
                && info.len() <= PAGE_BYTES * MAX_PAGES as u64 =>
        {
            Ok(())
        }
        Ok(_) => Err(CoreError::StorageRecoveryRequired),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if allow_create {
                Ok(())
            } else {
                Err(CoreError::StorageRecoveryRequired)
            }
        }
        Err(_) => Err(CoreError::StorageUnavailable),
    }
}

fn set_key(connection: &Connection, key: &[u8]) -> Result<(), CoreError> {
    // The fixed input is a random 256-bit key, not a user passphrase. SQLCipher
    // derives the authentication key with the file's per-database salt.
    let cipher_version: String = pragma(connection, "cipher_version")?;
    if !cipher_version.starts_with("4.") {
        return Err(CoreError::StorageUnavailable);
    }
    connection
        .execute_batch("PRAGMA cipher_log_level = NONE; PRAGMA cipher_memory_security = ON;")
        .map_err(sql_error)?;
    let mut statement = Zeroizing::new(String::with_capacity(96));
    statement.push_str("PRAGMA key = \"x'");
    for byte in key {
        write!(statement, "{byte:02x}").map_err(|_| CoreError::StorageUnavailable)?;
    }
    statement.push_str("'\";\0");
    connection.execute_batch(&statement).map_err(sql_error)?;
    drop(statement);
    let cipher_active: String = pragma(connection, "cipher_status")?;
    let hmac_enabled: String = pragma(connection, "cipher_use_hmac")?;
    if cipher_active != "1" || hmac_enabled != "1" {
        return Err(CoreError::StorageUnavailable);
    }
    connection
        .execute_batch(
            "PRAGMA temp_store = MEMORY;
         PRAGMA secure_delete = ON;
         PRAGMA mmap_size = 0;
         PRAGMA cache_size = -2048;
         PRAGMA synchronous = EXTRA;",
        )
        .map_err(sql_error)
}

fn initialize(connection: &Connection) -> Result<(), CoreError> {
    let objects: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
        .map_err(sql_error)?;
    if objects != 0 {
        return Err(CoreError::StorageRecoveryRequired);
    }
    connection.execute_batch(SCHEMA).map_err(sql_error)?;
    connection
        .execute_batch(PRIVATE_SCHEMA)
        .map_err(sql_error)?;
    connection
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(sql_error)?;
    connection
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(sql_error)?;
    let settings = encode_settings(&LocalSettings::default())?;
    connection
        .execute(
            "INSERT INTO local_config VALUES (1, ?1, ?2, ?3)",
            params![0u64.to_be_bytes(), 1u64.to_be_bytes(), settings],
        )
        .map_err(sql_error)?;
    Ok(())
}

fn check_cipher_integrity(connection: &Connection) -> Result<(), CoreError> {
    let mut statement = connection
        .prepare("PRAGMA cipher_integrity_check")
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    // SQLCipher emits only failing pages. Keep the page error detail private.
    if rows.next().map_err(sql_error)?.is_some() {
        return Err(CoreError::StorageRecoveryRequired);
    }
    Ok(())
}

fn pragma<T: rusqlite::types::FromSql>(
    connection: &Connection,
    name: &str,
) -> Result<T, CoreError> {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .map_err(sql_error)
}

fn decode_u64(row: &Row<'_>, column: usize) -> rusqlite::Result<u64> {
    row.get::<_, [u8; 8]>(column).map(u64::from_be_bytes)
}

fn encode_settings(settings: &LocalSettings) -> Result<Vec<u8>, CoreError> {
    let bytes = serde_json::to_vec(settings).map_err(|_| CoreError::StorageUnavailable)?;
    if bytes.is_empty() || bytes.len() > MAX_SETTINGS_BYTES {
        return Err(CoreError::StorageUnavailable);
    }
    Ok(bytes)
}

impl LocalConfigStore for SqlCipherStore {
    fn load_config(&self) -> Result<LoadedLocalConfig, CoreError> {
        self.connection
            .query_row(
                "SELECT generation, next_node_id, settings FROM local_config WHERE singleton = 1",
                [],
                |row| {
                    let blob = row.get_ref(2)?.as_blob()?;
                    let settings = if (1..=MAX_SETTINGS_BYTES).contains(&blob.len()) {
                        serde_json::from_slice(blob).ok()
                    } else {
                        None
                    };
                    Ok(LoadedLocalConfig {
                        generation: decode_u64(row, 0)?,
                        next_node_id: decode_u64(row, 1)?,
                        settings: settings.ok_or(Error::InvalidQuery)?,
                    })
                },
            )
            .map_err(read_error)
    }

    fn visit_nodes(
        &self,
        visitor: &mut dyn FnMut(u64, &str) -> Result<(), CoreError>,
    ) -> Result<(), CoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT id, uri FROM local_nodes ORDER BY id")
            .map_err(read_error)?;
        let mut rows = statement.query([]).map_err(read_error)?;
        let mut count = 0;
        while let Some(row) = rows.next().map_err(read_error)? {
            count += 1;
            let id = decode_u64(row, 0).map_err(read_error)?;
            let raw = row
                .get_ref(1)
                .and_then(|value| Ok(value.as_blob()?))
                .map_err(read_error)?;
            if count > MAX_NODES || !(1..=MAX_NODE_INPUT_BYTES).contains(&raw.len()) {
                return Err(CoreError::StorageRecoveryRequired);
            }
            let raw = std::str::from_utf8(raw).map_err(|_| CoreError::StorageRecoveryRequired)?;
            visitor(id, raw)?;
        }
        Ok(())
    }

    fn load_private(&self, record: PrivateRecord) -> Result<Option<Zeroizing<Vec<u8>>>, CoreError> {
        let (id, limit) = private_record(record);
        let mut statement = self
            .connection
            .prepare("SELECT data FROM local_private WHERE kind = ?1")
            .map_err(read_error)?;
        let mut rows = statement.query([id]).map_err(read_error)?;
        let Some(row) = rows.next().map_err(read_error)? else {
            return Ok(None);
        };
        let bytes = row
            .get_ref(0)
            .and_then(|value| Ok(value.as_blob()?))
            .map_err(read_error)?;
        if !(1..=limit).contains(&bytes.len()) {
            return Err(CoreError::StorageRecoveryRequired);
        }
        Ok(Some(Zeroizing::new(bytes.to_vec())))
    }

    fn commit_private(
        &mut self,
        record: PrivateRecord,
        data: Option<&[u8]>,
    ) -> Result<(), CoreError> {
        let (id, limit) = private_record(record);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        match data {
            Some(bytes) if (1..=limit).contains(&bytes.len()) => transaction.execute(
                "INSERT INTO local_private VALUES (?1, ?2) ON CONFLICT(kind) DO UPDATE SET data=excluded.data",
                params![id, bytes],
            ).map_err(sql_error)?,
            Some(_) => return Err(CoreError::StorageUnavailable),
            None => transaction.execute("DELETE FROM local_private WHERE kind = ?1", [id]).map_err(sql_error)?,
        };
        transaction.commit().map_err(commit_error)
    }

    fn commit(&mut self, generation: u64, edit: LocalConfigEdit<'_>) -> Result<(), CoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let generation = generation.to_be_bytes();
        let updated = match edit {
            LocalConfigEdit::ImportNode { id, uri } => {
                let next = id.checked_add(1).ok_or(CoreError::GenerationExhausted)?;
                transaction.execute("INSERT INTO local_nodes VALUES (?1, ?2)", params![id.to_be_bytes(), uri.as_bytes()]).map_err(sql_error)?;
                transaction.execute(
                    "UPDATE local_config SET generation = ?1, next_node_id = ?2 WHERE singleton = 1 AND generation < ?1 AND next_node_id = ?3",
                    params![generation, next.to_be_bytes(), id.to_be_bytes()],
                )
            }
            LocalConfigEdit::RemoveNode { id } => {
                let deleted = transaction.execute("DELETE FROM local_nodes WHERE id = ?1", params![id.to_be_bytes()]).map_err(sql_error)?;
                if deleted != 1 {
                    return Err(CoreError::StorageRecoveryRequired);
                }
                transaction.execute("UPDATE local_config SET generation = ?1 WHERE singleton = 1 AND generation < ?1", params![generation])
            }
            LocalConfigEdit::Settings { settings, clear_hub } => {
                if clear_hub {
                    transaction.execute("DELETE FROM local_private WHERE kind = 2", []).map_err(sql_error)?;
                }
                transaction.execute(
                "UPDATE local_config SET generation = ?1, settings = ?2 WHERE singleton = 1 AND generation < ?1",
                params![generation, encode_settings(settings)?],
                )
            }
        }.map_err(sql_error)?;
        if updated != 1 {
            return Err(CoreError::StorageRecoveryRequired);
        }
        transaction.commit().map_err(commit_error)
    }
}

fn private_record(record: PrivateRecord) -> (u32, usize) {
    match record {
        PrivateRecord::Vault => (1, VAULT_IMAGE_LIMIT),
        PrivateRecord::Hub => (2, HUB_SESSION_LIMIT),
        PrivateRecord::Protection => (3, PROTECTION_IMAGE_LIMIT),
        PrivateRecord::Notes => (4, NOTES_IMAGE_LIMIT),
    }
}

fn commit_error(error: Error) -> CoreError {
    match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked | ErrorCode::DiskFull) => {
            CoreError::StorageUnavailable
        }
        _ => CoreError::StorageRecoveryRequired,
    }
}

fn sql_error(error: Error) -> CoreError {
    match error.sqlite_error_code() {
        Some(ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt) => {
            CoreError::StorageRecoveryRequired
        }
        _ => CoreError::StorageUnavailable,
    }
}

fn read_error(error: Error) -> CoreError {
    match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked | ErrorCode::SystemIoFailure) => {
            CoreError::StorageUnavailable
        }
        _ => CoreError::StorageRecoveryRequired,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loft_core::{ConnectionState, CoreState};
    use std::{
        process::Command,
        sync::{Arc, atomic::AtomicBool},
    };

    const FIXTURE_KEY: [u8; 32] = [57; 32];

    #[test]
    fn authenticated_schema_one_upgrades_and_keeps_guest_preferences() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy.db");
        let db = SqlCipherStore::open(&path, &FIXTURE_KEY, true).unwrap();
        let mut core = CoreState::with_local_storage(Arc::new(AtomicBool::new(false)), db).unwrap();
        core.stage_server("saved.example".to_owned()).unwrap();
        drop(core);
        let connection = Connection::open(&path).unwrap();
        set_key(&connection, &FIXTURE_KEY).unwrap();
        connection
            .execute_batch("DROP TABLE local_private; PRAGMA user_version = 1")
            .unwrap();
        drop(connection);

        let db = SqlCipherStore::open(&path, &FIXTURE_KEY, false).unwrap();
        assert_eq!(
            pragma::<u32>(&db.connection, "user_version").unwrap(),
            SCHEMA_VERSION
        );
        let mut core = CoreState::with_local_storage(Arc::new(AtomicBool::new(false)), db).unwrap();
        assert_eq!(
            core.snapshot().server_address.as_deref(),
            Some("https://saved.example")
        );
        assert!(core.vault_list(false, 0, None).unwrap().entries.is_empty());
        assert!(core.hub_snapshot().session.is_none());
    }

    #[test]
    fn exclusive_connection_releases_on_close() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.db");
        let first = SqlCipherStore::open(&path, &FIXTURE_KEY, true).unwrap();
        assert!(matches!(
            SqlCipherStore::open(&path, &FIXTURE_KEY, false),
            Err(CoreError::StorageUnavailable)
        ));
        drop(first);
        assert!(SqlCipherStore::open(&path, &FIXTURE_KEY, false).is_ok());
    }

    #[test]
    fn write_failure_leaves_published_and_durable_configuration_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.db");
        let store = SqlCipherStore::open(&path, &FIXTURE_KEY, true).unwrap();
        // SQLite executes the node INSERT first. Force its subsequent config UPDATE to fail.
        store
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER fixture_fail_update BEFORE UPDATE ON local_config
             BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END;",
            )
            .unwrap();
        let mut core = CoreState::with_local_storage(stop_signal(), store).unwrap();
        let before = core.snapshot();
        assert_eq!(
            core.import_node("socks5://temporary.example".into()),
            Err(CoreError::StorageUnavailable)
        );
        assert_eq!(core.snapshot(), before);
        drop(core);
        let store = SqlCipherStore::open(&path, &FIXTURE_KEY, false).unwrap();
        let mut reopened = CoreState::with_local_storage(stop_signal(), store).unwrap();
        assert_eq!(reopened.snapshot(), before);
        let receipt = reopened
            .import_node("socks5://recovered.example".into())
            .unwrap();
        assert_eq!(receipt.id, "node-0000000000000001");
    }

    #[test]
    fn future_schema_and_tampered_page_preserve_data_and_require_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.db");
        let store = SqlCipherStore::open(&path, &FIXTURE_KEY, true).unwrap();
        store
            .connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        drop(store);
        let future = fs::read(&path).unwrap();
        assert!(matches!(
            SqlCipherStore::open(&path, &FIXTURE_KEY, true),
            Err(CoreError::StorageRecoveryRequired)
        ));
        assert_eq!(fs::read(&path).unwrap(), future);

        let path = directory.path().join("tampered.db");
        drop(SqlCipherStore::open(&path, &FIXTURE_KEY, true).unwrap());
        let mut tampered = fs::read(&path).unwrap();
        assert!(tampered.len() > PAGE_BYTES as usize + 32);
        tampered[PAGE_BYTES as usize + 32] ^= 1;
        fs::write(&path, &tampered).unwrap();
        assert!(matches!(
            SqlCipherStore::open(&path, &FIXTURE_KEY, false),
            Err(CoreError::StorageRecoveryRequired)
        ));
        assert_eq!(fs::read(&path).unwrap(), tampered);
    }

    #[test]
    fn uncommitted_database_write_is_rolled_back_after_process_exit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.db");
        let store = SqlCipherStore::open(&path, &FIXTURE_KEY, true).unwrap();
        let mut core = CoreState::with_local_storage(stop_signal(), store).unwrap();
        let saved = core.import_node("socks5://fixture.example".into()).unwrap();
        drop(core);
        let process = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::process_exit_fixture")
            .env("LOFT_STORAGE_PROCESS_EXIT_FIXTURE", &path)
            .output()
            .unwrap();
        assert_eq!(process.status.code(), Some(73));
        // A dirty page spills before process exit. The actual rollback journal remains present.
        assert!(
            directory
                .path()
                .join("vault.db-journal")
                .metadata()
                .unwrap()
                .len()
                > 512
        );
        let store = SqlCipherStore::open(&path, &FIXTURE_KEY, false).unwrap();
        let mut reopened = CoreState::with_local_storage(stop_signal(), store).unwrap();
        assert_eq!(reopened.snapshot().nodes, vec![saved]);
        assert_eq!(
            reopened.snapshot().connection_state,
            ConnectionState::Disconnected
        );
        let next = reopened
            .import_node("socks5://next.example".into())
            .unwrap();
        assert_eq!(next.id, "node-0000000000000002");
    }

    #[test]
    fn process_exit_fixture() {
        let Some(path) = std::env::var_os("LOFT_STORAGE_PROCESS_EXIT_FIXTURE") else {
            return;
        };
        let mut store = SqlCipherStore::open(Path::new(&path), &FIXTURE_KEY, false).unwrap();
        store
            .connection
            .pragma_update(None, "cache_size", 4)
            .unwrap();
        let write = store.connection.transaction().unwrap();
        write
            .execute(
                "INSERT INTO local_nodes VALUES (?1, ?2)",
                params![2u64.to_be_bytes(), vec![7u8; 128 * 1024]],
            )
            .unwrap();
        write
            .execute(
                "UPDATE local_config SET generation = ?1, next_node_id = ?2",
                params![2u64.to_be_bytes(), 3u64.to_be_bytes()],
            )
            .unwrap();
        std::process::exit(73);
    }

    fn stop_signal() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }
}
