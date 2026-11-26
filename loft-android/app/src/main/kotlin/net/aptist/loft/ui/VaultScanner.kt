package net.aptist.loft.ui

import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

@Composable
internal fun VaultScanner(modifier: Modifier, onRead: (String) -> Unit, onUnavailable: () -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val previewView = remember(context) { PreviewView(context).apply { implementationMode = PreviewView.ImplementationMode.COMPATIBLE } }
    val read = rememberUpdatedState(onRead)
    val unavailable = rememberUpdatedState(onUnavailable)
    DisposableEffect(context, lifecycleOwner, previewView) {
        val executor = Executors.newSingleThreadExecutor()
        val closed = AtomicBoolean(false)
        val delivered = AtomicBoolean(false)
        val preview = Preview.Builder().build().apply { setSurfaceProvider(previewView.surfaceProvider) }
        val analysis = ImageAnalysis.Builder().setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST).build()
        val main = ContextCompat.getMainExecutor(context)
        val future = ProcessCameraProvider.getInstance(context)
        var provider: ProcessCameraProvider? = null
        analysis.setAnalyzer(executor) { image ->
            try {
                if (!closed.get() && !delivered.get()) decodeVaultQr(image)?.let { value ->
                    if (delivered.compareAndSet(false, true)) main.execute { if (!closed.get()) read.value(value) }
                }
            } finally { image.close() }
        }
        future.addListener({
            if (!closed.get()) {
                try {
                    provider = future.get().also { camera ->
                        val selector = if (camera.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA)) CameraSelector.DEFAULT_BACK_CAMERA else CameraSelector.DEFAULT_FRONT_CAMERA
                        camera.bindToLifecycle(lifecycleOwner, selector, preview, analysis)
                    }
                } catch (_: Exception) { unavailable.value() }
            }
        }, main)
        onDispose {
            closed.set(true)
            analysis.clearAnalyzer()
            provider?.unbind(preview, analysis)
            executor.shutdown()
        }
    }
    AndroidView(factory = { previewView }, modifier = modifier)
}

private fun decodeVaultQr(image: ImageProxy): String? {
    val y = image.planes.firstOrNull() ?: return null
    val width = image.width
    val height = image.height
    if (width !in 1..1920 || height !in 1..1920 || width.toLong() * height > 2_073_600 || y.pixelStride != 1 || y.rowStride < width) return null
    val input = y.buffer.duplicate()
    val start = input.position()
    if (input.remaining().toLong() < (height - 1L) * y.rowStride + width) return null
    val luma = ByteArray(width * height)
    return try {
        for (row in 0 until height) {
            input.position(start + row * y.rowStride)
            input.get(luma, row * width, width)
        }
        val source = PlanarYUVLuminanceSource(luma, width, height, 0, 0, width, height, false)
        val result = QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE))).text
        result.takeIf { it.length <= 4096 && it.startsWith("otpauth://", ignoreCase = true) }
    } catch (_: ReaderException) { null }
    finally { luma.fill(0) }
}
