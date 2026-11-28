package net.aptist.loft.ui.notes

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.isImeVisible
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.InputTransformation
import androidx.compose.foundation.text.input.OutputTransformation
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.isSensitiveData
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import net.aptist.loft.R
import net.aptist.loft.core.generated.NoteDetail
import net.aptist.loft.core.generated.NotesDraft
import net.aptist.loft.ui.LocalLoftColors

internal const val NOTE_TITLE_LIMIT = 240
internal const val NOTE_BODY_LIMIT = 25 * 1024
internal const val NOTE_TAGS_LIMIT = 1024
internal const val NOTE_ICON_LIMIT = 64

/** The editor fields, cursor and undo buffers live in this page's composition only. */
internal class NotesEditor(detail: NoteDetail?) {
    private val originalTitle = detail?.summary?.title.orEmpty()
    private val originalBody = detail?.body.orEmpty()
    private val originalIcon = detail?.summary?.icon.orEmpty()
    private val originalTags = detail?.summary?.tags?.joinToString(", ").orEmpty()
    private val id = detail?.summary?.id
    private val version = detail?.summary?.version
    val updatedAt = detail?.summary?.updatedAt
    val title = TextFieldState(originalTitle)
    val body = TextFieldState(originalBody)
    val icon = TextFieldState(originalIcon)
    val tags = TextFieldState(originalTags)

    val hasContent: Boolean get() = title.text.isNotBlank() || body.text.isNotBlank()
    val edited: Boolean get() = originalTitle != title.text.toString() || originalBody != body.text.toString() ||
        originalIcon != icon.text.toString() || originalTags != tags.text.toString()

    fun draft() = NotesDraft(id, title.text.toString(), body.text.toString(), icon.text.toString().ifBlank { null },
        tags.text.toString(), version)

    override fun toString() = "NotesEditor(<private>)"
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun NotesEditorPane(
    editor: NotesEditor,
    busy: Boolean,
    status: String?,
    onBack: () -> Unit,
    onSave: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val colors = MaterialTheme.colorScheme
    val dark = colors.onSurface == Color.White
    val paper = if (dark) Color(0xFF181D26) else Color(0xFFFEFEFF)
    val line = if (dark) Color(0xFF30394A) else Color(0xFFE5EBF6)
    val margin = if (dark) Color(0xFF514C6A) else Color(0xFFD6D8F5)
    val editorText = MaterialTheme.typography.bodyLarge
    val heading = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.SemiBold)
    var discard by remember(editor) { mutableStateOf(false) }
    fun close() {
        if (editor.edited) discard = true else onBack()
    }
    val keyboard = LocalSoftwareKeyboardController.current
    val imeVisible = WindowInsets.isImeVisible
    androidx.activity.compose.BackHandler {
        if (imeVisible) keyboard?.hide() else if (!busy) close()
    }
    if (discard) {
        AlertDialog(onDismissRequest = { discard = false }, title = { Text(stringResource(R.string.notes_discard_title)) },
            properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
            text = { Text(stringResource(R.string.notes_discard_body)) },
            confirmButton = { TextButton(onClick = onBack) { Text(stringResource(R.string.notes_discard)) } },
            dismissButton = { TextButton(onClick = { discard = false }) { Text(stringResource(R.string.cancel)) } })
    }
    Column(modifier.fillMaxSize().background(paper)) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
            NotesIconButton(R.drawable.ic_arrow_back, R.string.navigate_back, onClick = ::close, enabled = !busy)
            Button(onClick = onSave, enabled = editor.hasContent && editor.edited && !busy) {
                Text(stringResource(R.string.notes_save))
            }
        }
        NotesNotice(status, Modifier.padding(horizontal = 20.dp))
        Box(Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()), contentAlignment = Alignment.TopCenter) {
            Column(Modifier.widthIn(max = 660.dp).fillMaxWidth().padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)) {
                NoteField(editor.title, R.string.notes_note_title, heading, NOTE_TITLE_LIMIT, enabled = !busy)
                editor.updatedAt?.let {
                    Text(formatNotesDate(it), color = LocalLoftColors.current.secondaryText,
                        style = MaterialTheme.typography.bodySmall)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    NoteField(editor.icon, R.string.notes_emoji, MaterialTheme.typography.bodyMedium, NOTE_ICON_LIMIT,
                        modifier = Modifier.widthIn(min = 56.dp, max = 84.dp), enabled = !busy)
                    NoteField(editor.tags, R.string.notes_tags_hint, MaterialTheme.typography.bodyMedium, NOTE_TAGS_LIMIT,
                        modifier = Modifier.weight(1f), enabled = !busy)
                }
                val lineHeight = editorText.lineHeight
                Box(Modifier.fillMaxWidth().heightIn(min = 440.dp).drawBehind {
                    val step = lineHeight.toPx()
                    if (step > 0) {
                        var y = step
                        while (y < size.height) {
                            drawLine(line, Offset(0f, y), Offset(size.width, y), 1.dp.toPx())
                            y += step
                        }
                    }
                    val x = 9.dp.toPx()
                    drawLine(margin, Offset(x, 0f), Offset(x, size.height), 1.dp.toPx())
                }) {
                    MarkdownField(editor.body, editorText, !busy, Modifier.fillMaxWidth().padding(start = 19.dp, end = 8.dp))
                }
            }
        }
    }
}

@Composable
internal fun NoteField(
    state: TextFieldState,
    label: Int,
    style: TextStyle,
    byteLimit: Int,
    modifier: Modifier = Modifier.fillMaxWidth(),
    enabled: Boolean = true,
    hideValue: Boolean = false,
) {
    val colors = MaterialTheme.colorScheme
    val description = stringResource(label)
    val limit = remember(byteLimit) { InputTransformation { if (!withinUtf8Limit(asCharSequence(), byteLimit)) revertAllChanges() } }
    BasicTextField(state = state, modifier = modifier.heightIn(min = 48.dp).semantics {
        contentDescription = description
        isSensitiveData = true
    }, enabled = enabled, textStyle = style.copy(color = colors.onSurface),
        lineLimits = TextFieldLineLimits.SingleLine, cursorBrush = SolidColor(colors.primary),
        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false,
            keyboardType = if (hideValue) KeyboardType.Password else KeyboardType.Text), inputTransformation = limit,
        outputTransformation = if (hideValue) OutputTransformation {
            replace(0, length, "•".repeat(length))
        } else null,
        decorator = { inner ->
            Box(contentAlignment = Alignment.CenterStart) {
                if (state.text.isEmpty()) Text(description, style = style, color = colors.onSurfaceVariant)
                inner()
            }
        })
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun MarkdownField(state: TextFieldState, style: TextStyle, enabled: Boolean, modifier: Modifier) {
    val colors = MaterialTheme.colorScheme
    val link = LocalLoftColors.current.link
    val description = stringResource(R.string.notes_markdown_body)
    var focused by remember { mutableStateOf(false) }
    val raw = state.text.toString()
    val document = remember(raw) { NotesMarkdown.parse(raw) }
    val composition = state.composition
    val input = remember(state) {
        InputTransformation {
            if (changes.changeCount == 1 && state.composition == null) {
                val before = changes.getOriginalRange(0)
                val after = changes.getRange(0)
                completeMarkdown(originalText.toString(), before.min, before.max,
                    asCharSequence().subSequence(after.min, after.max).toString())?.let { edit ->
                    replace(edit.start, edit.end, edit.replacement)
                    selection = TextRange(edit.cursor)
                }
            }
            if (!withinUtf8Limit(asCharSequence(), NOTE_BODY_LIMIT)) revertAllChanges()
        }
    }
    val presentation = remember(document, raw, focused, composition, link) {
        OutputTransformation {
            val start = if (focused) minOf(originalSelection.min, composition?.min ?: Int.MAX_VALUE) else null
            val end = if (focused) maxOf(originalSelection.max, composition?.max ?: 0) else null
            if (!raw.contentEquals(originalText)) return@OutputTransformation
            val projection = document.project(start, end)
            for (edit in projection.edits.asReversed()) replace(edit.start, edit.end, edit.replacement)
            for (mark in projection.marks) addStyle(mark.format.style(link), mark.start, mark.end)
        }
    }
    BasicTextField(state = state, modifier = modifier.onFocusChanged { focused = it.isFocused }.semantics {
        contentDescription = description
        isSensitiveData = true
    }, enabled = enabled, inputTransformation = input, outputTransformation = presentation,
        textStyle = style.copy(color = colors.onSurface), cursorBrush = SolidColor(colors.primary),
        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
        decorator = { inner ->
            Box {
                if (state.text.isEmpty()) Text(description, style = style, color = colors.onSurfaceVariant)
                inner()
            }
        })
}

private fun NoteFormat.style(link: Color): SpanStyle = when (this) {
    is NoteFormat.Heading -> SpanStyle(fontSize = when (level) { 1 -> 24.sp; 2 -> 21.sp; else -> 18.sp },
        fontWeight = FontWeight.SemiBold)
    NoteFormat.Strong -> SpanStyle(fontWeight = FontWeight.Bold)
    NoteFormat.Emphasis -> SpanStyle(fontStyle = FontStyle.Italic)
    NoteFormat.Strike -> SpanStyle(textDecoration = TextDecoration.LineThrough)
    NoteFormat.Link -> SpanStyle(color = link, textDecoration = TextDecoration.Underline)
    NoteFormat.Quote -> SpanStyle(color = link.copy(alpha = 0.92f))
    NoteFormat.Code, NoteFormat.Table -> SpanStyle(fontFamily = FontFamily.Monospace)
}

internal fun withinUtf8Limit(text: CharSequence, limit: Int): Boolean {
    var remaining = limit
    var index = 0
    while (index < text.length) {
        val character = text[index++]
        remaining -= when {
            character.code <= 0x7f -> 1
            character.code <= 0x7ff -> 2
            character.isHighSurrogate() && index < text.length && text[index].isLowSurrogate() -> {
                index++
                4
            }
            else -> 3
        }
        if (remaining < 0) return false
    }
    return true
}
