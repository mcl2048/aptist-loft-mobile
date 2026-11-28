package net.aptist.loft

import android.content.ClipDescription
import androidx.test.ext.junit.runners.AndroidJUnit4
import net.aptist.loft.ui.notes.notesPairingClip
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SecureNotesClipboardTest {
    @Test fun keyIsPlainTextWithSensitivePreviewMetadata() {
        val synthetic = "_".repeat(42) + "A"
        val clip = notesPairingClip("Pairing key", synthetic)
        assertEquals("Pairing key", clip.description.label)
        assertTrue(clip.description.hasMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN))
        assertTrue(clip.description.extras?.getBoolean(ClipDescription.EXTRA_IS_SENSITIVE) == true)
        assertEquals(1, clip.itemCount)
        assertTrue(clip.getItemAt(0).text.contentEquals(synthetic))
    }
}
