package net.aptist.loft.ui.notes

import androidx.activity.compose.BackHandler
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.isImeVisible
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.absoluteOffset
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.isSensitiveData
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import kotlinx.coroutines.delay
import net.aptist.loft.R
import net.aptist.loft.core.generated.NoteSummary
import net.aptist.loft.core.generated.NoteTag
import net.aptist.loft.core.generated.NotesPage
import net.aptist.loft.foundation.PaneBounds
import net.aptist.loft.service.NotesCommand
import net.aptist.loft.service.NotesResult
import net.aptist.loft.ui.LocalLoftColors
import java.text.DateFormat
import java.util.Date
import kotlin.math.roundToInt

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun SecureNotesScreen(
    modifier: Modifier,
    execute: (NotesCommand, (String, NotesResult?) -> Unit) -> Boolean,
    primary: PaneBounds? = null,
    secondary: PaneBounds? = null,
    refreshGeneration: Long = 0,
    onOpenAccount: () -> Unit = {},
) {
    val requests = remember { NotesRequests() }
    val search = remember { TextFieldState() }
    var editor by remember { mutableStateOf<NotesEditor?>(null) }
    var archived by remember { mutableStateOf(false) }
    var activeTag by remember { mutableStateOf<String?>(null) }
    var tags by remember { mutableStateOf<List<NoteTag>?>(null) }
    var syncOpen by remember { mutableStateOf(false) }
    var delete by remember { mutableStateOf<NoteSummary?>(null) }
    var offset by remember { mutableStateOf(0u) }
    var page by remember { mutableStateOf<NotesPage?>(null) }
    var pageQuery by remember { mutableStateOf("") }
    var revision by remember { mutableIntStateOf(0) }
    val query = search.text.toString().trim()
    val keyboard = LocalSoftwareKeyboardController.current
    val imeVisible = WindowInsets.isImeVisible
    val scroll = androidx.compose.foundation.lazy.rememberLazyListState()
    fun resetPage() {
        page = null
        offset = 0u
        requests.listFailed = false
        revision++
    }
    fun changeArchive(value: Boolean) {
        if (archived == value) return
        archived = value
        activeTag = null
        resetPage()
    }
    fun archive(note: NoteSummary) {
        requests.submit(execute, NotesCommand.Archive(note.id, !note.archived)) { resetPage() }
    }
    fun remove(note: NoteSummary) {
        requests.submit(execute, NotesCommand.Delete(note.id)) {
            delete = null
            resetPage()
        }
    }

    DisposableEffect(requests) { onDispose { requests.dispose() } }
    LaunchedEffect(refreshGeneration) { if (refreshGeneration != 0L) resetPage() }
    LaunchedEffect(archived, query, activeTag, offset, revision, requests.busy) {
        if (requests.busy || (page != null && pageQuery == query)) return@LaunchedEffect
        if (query != pageQuery) delay(160)
        val requestedRevision = revision
        val targetOffset = offset.takeIf { query == pageQuery } ?: 0u
        requests.submit(execute, NotesCommand.ListPage(archived, query, activeTag, targetOffset,
            requests.generation.takeIf { targetOffset != 0u }),
            onError = { code ->
                if (revision == requestedRevision) {
                    if (code == "conflict" && targetOffset != 0u) resetPage()
                    else requests.failList(query)
                }
            }) { result ->
            val incoming = (result as? NotesResult.Page)?.value ?: return@submit
            if (revision != requestedRevision || query != search.text.toString().trim()) return@submit
            requests.generation = incoming.generation
            pageQuery = query
            offset = targetOffset
            page = incoming
        }
    }
    LaunchedEffect(archived, query, activeTag, offset, revision) {
        scroll.scrollToItem(0)
    }
    BackHandler(enabled = editor == null && (requests.busy || archived || activeTag != null)) {
        if (imeVisible) keyboard?.hide()
        else if (!requests.busy) {
            if (activeTag != null) { activeTag = null; resetPage() } else changeArchive(false)
        }
    }

    PrivateEditorInput {
        BoxWithConstraints(modifier.fillMaxSize().semantics { isSensitiveData = true },
            contentAlignment = Alignment.TopCenter) {
            val currentEditor = editor
            val split = currentEditor != null && maxWidth >= 684.dp && maxHeight >= 340.dp
            val list: @Composable (Modifier) -> Unit = { listModifier ->
                NotesDirectory(
                    modifier = listModifier, archived = archived, activeTag = activeTag,
                    search = search, busy = requests.busy, status = requests.status, editing = currentEditor != null,
                    page = page.takeIf { query == pageQuery }, previousPage = offset > 0u, scroll = scroll,
                    onOpen = { entry ->
                        if (editor == null) requests.submit(execute, NotesCommand.Detail(entry.id)) { result ->
                            (result as? NotesResult.Detail)?.value?.let { editor = NotesEditor(it) }
                        }
                    },
                    onArchive = ::archive, onDelete = ::remove, onConfirmDelete = { delete = it },
                    onCreate = { if (editor == null) editor = NotesEditor(null) }, onToggleArchive = { changeArchive(!archived) },
                    onClearTag = { activeTag = null; resetPage() },
                    onTagWall = {
                        requests.submit(execute, NotesCommand.Tags(archived)) { result ->
                            tags = (result as? NotesResult.Tags)?.value
                        }
                    },
                    onSync = { syncOpen = true }, onRetry = { resetPage() },
                    onPrevious = {
                        offset = (offset.toInt() - 20).coerceAtLeast(0).toUInt()
                        page = null
                        requests.listFailed = false
                    },
                    onNext = {
                        page?.nextOffset?.let { next -> offset = next; page = null; requests.listFailed = false }
                    },
                )
            }
            val edit: @Composable (Modifier) -> Unit = { editorModifier ->
                if (currentEditor != null) {
                    NotesEditorPane(currentEditor, requests.busy, requests.status, onBack = {
                        editor = null
                        requests.status = null
                    }, onSave = {
                        requests.submit(execute, NotesCommand.Save(currentEditor.draft())) { result ->
                            if (result is NotesResult.Saved) {
                                editor = null
                                resetPage()
                            }
                        }
                    }, modifier = editorModifier)
                }
            }
            if (primary != null) {
                if (secondary != null || currentEditor == null) NotesPane(primary, list)
                if (currentEditor != null) NotesPane(secondary ?: primary, edit)
            } else if (split) {
                Row(Modifier.fillMaxSize()) {
                    list(Modifier.weight(0.39f).fillMaxHeight())
                    VerticalDivider()
                    edit(Modifier.weight(0.61f).fillMaxHeight())
                }
            } else if (currentEditor != null) edit(Modifier.fillMaxSize())
            else list(Modifier.widthIn(max = 800.dp).fillMaxSize())
        }
        tags?.let { values ->
            NotesTagWall(values, onDismiss = { tags = null }, onChoose = { tag ->
                activeTag = tag
                tags = null
                resetPage()
            })
        }
        delete?.let { entry ->
            AlertDialog(
                properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
                onDismissRequest = { if (!requests.busy) delete = null },
                title = { Text(stringResource(R.string.notes_delete_title)) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(stringResource(R.string.notes_delete_body))
                        NotesNotice(requests.status)
                    }
                },
                confirmButton = {
                    TextButton(onClick = { remove(entry) }, enabled = !requests.busy) {
                        Text(stringResource(R.string.notes_delete), color = MaterialTheme.colorScheme.error)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { delete = null }, enabled = !requests.busy) { Text(stringResource(R.string.cancel)) }
                },
            )
        }
        if (syncOpen) NotesSyncDialog(requests, execute, refreshGeneration, onOpenAccount) {
            syncOpen = false
            resetPage()
        }
    }
}

@Composable
private fun NotesPane(bounds: PaneBounds, content: @Composable (Modifier) -> Unit) {
    Box(Modifier.alignTo(bounds)) { content(Modifier.fillMaxSize()) }
}

private fun Modifier.alignTo(bounds: PaneBounds): Modifier =
    offset(bounds.left.dp, bounds.top.dp).size(bounds.width.dp, bounds.height.dp).clipToBounds()

internal class NotesRequests {
    var busy by mutableStateOf(false)
        private set
    var status by mutableStateOf<String?>(null)
    var listFailed by mutableStateOf(false)
    var generation: ULong? = null
    private var failedQuery: String? = null
    private var active = true

    fun dispose() { active = false }

    fun failList(query: String) {
        failedQuery = query
        listFailed = true
    }

    fun submit(
        execute: (NotesCommand, (String, NotesResult?) -> Unit) -> Boolean,
        command: NotesCommand,
        onError: ((String) -> Unit)? = null,
        onSuccess: (NotesResult?) -> Unit,
    ) {
        if (!active || busy || (listFailed && command is NotesCommand.ListPage && command.query == failedQuery)) {
            command.clear()
            return
        }
        busy = true
        status = null
        val admitted = execute(command) { code, result ->
            if (active) {
                busy = false
                if (code == "ok") onSuccess(result) else {
                    status = code
                    onError?.invoke(code)
                }
            }
        }
        if (!admitted) {
            busy = false
            status = "unavailable"
            onError?.invoke("unavailable")
            command.clear()
        }
    }
}

@Composable
private fun NotesDirectory(
    modifier: Modifier,
    archived: Boolean,
    activeTag: String?,
    search: TextFieldState,
    busy: Boolean,
    status: String?,
    editing: Boolean,
    page: NotesPage?,
    previousPage: Boolean,
    scroll: androidx.compose.foundation.lazy.LazyListState,
    onOpen: (NoteSummary) -> Unit,
    onArchive: (NoteSummary) -> Unit,
    onDelete: (NoteSummary) -> Unit,
    onConfirmDelete: (NoteSummary) -> Unit,
    onCreate: () -> Unit,
    onToggleArchive: () -> Unit,
    onClearTag: () -> Unit,
    onTagWall: () -> Unit,
    onSync: () -> Unit,
    onRetry: () -> Unit,
    onPrevious: () -> Unit,
    onNext: () -> Unit,
) {
    Column(modifier.padding(horizontal = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) {
            Text(stringResource(if (archived) R.string.notes_archive_title else R.string.notes_title),
                style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f).semantics { heading() })
            NotesIconButton(R.drawable.ic_notes_sync, R.string.notes_sync, onSync, enabled = !busy)
        }
        Surface(shape = MaterialTheme.shapes.medium, color = MaterialTheme.colorScheme.surfaceVariant) {
            Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp), verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Icon(painterResource(R.drawable.ic_notes_search), null, Modifier.size(20.dp), tint = LocalLoftColors.current.secondaryText)
                NoteField(search, R.string.notes_search, MaterialTheme.typography.bodyMedium, 256,
                    modifier = Modifier.weight(1f))
            }
        }
        activeTag?.let { tag ->
            TextButton(onClick = onClearTag) {
                Text(stringResource(R.string.notes_remove_filter, tag), maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
        NotesNotice(status, Modifier.padding(top = 6.dp))
        if (page == null && status != null && !busy) {
            TextButton(onClick = onRetry) { Text(stringResource(R.string.notes_retry)) }
        }
        Box(Modifier.weight(1f).fillMaxWidth()) {
            LazyColumn(state = scroll, modifier = Modifier.fillMaxSize()) {
                if (page?.entries?.isEmpty() == true) {
                    item {
                        Column(Modifier.fillMaxWidth().padding(vertical = 38.dp, horizontal = 8.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Icon(painterResource(R.drawable.ic_secure_notes), null, Modifier.size(32.dp), tint = LocalLoftColors.current.link)
                            Text(stringResource(when {
                                search.text.isNotBlank() || activeTag != null -> R.string.notes_no_matches
                                archived -> R.string.notes_no_archive
                                else -> R.string.notes_empty
                            }), style = MaterialTheme.typography.titleMedium)
                            if (!archived && search.text.isBlank() && activeTag == null) {
                                Text(stringResource(R.string.notes_empty_help), style = MaterialTheme.typography.bodyMedium,
                                    color = LocalLoftColors.current.secondaryText)
                            }
                        }
                    }
                }
                items(page?.entries.orEmpty(), key = { it.id }) { entry ->
                    NotesRow(entry, enabled = !busy, canOpen = !editing, onOpen = { onOpen(entry) }, onArchive = { onArchive(entry) },
                        onDelete = { onDelete(entry) }, onConfirmDelete = { onConfirmDelete(entry) })
                    HorizontalDivider(color = LocalLoftColors.current.divider)
                }
                if (previousPage || page?.nextOffset != null) {
                    item {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            if (previousPage) TextButton(onClick = onPrevious, enabled = !busy) {
                                Text(stringResource(R.string.notes_previous))
                            } else Spacer(Modifier)
                            if (page?.nextOffset != null) TextButton(onClick = onNext, enabled = !busy) {
                                Text(stringResource(R.string.notes_next))
                            }
                        }
                    }
                }
            }
            if (busy && page == null) CircularProgressIndicator(Modifier.align(Alignment.Center).size(32.dp))
        }
        Row(Modifier.fillMaxWidth().padding(vertical = 10.dp), horizontalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterHorizontally),
            verticalAlignment = Alignment.CenterVertically) {
            NotesRoundButton(R.drawable.ic_notes_archive, if (archived) R.string.notes_active else R.string.notes_archive_title,
                primary = false, selected = archived, enabled = !busy, onClick = onToggleArchive)
            NotesRoundButton(R.drawable.ic_add, R.string.notes_create, primary = true, selected = false,
                enabled = !busy && !editing, onClick = onCreate)
            NotesRoundButton(R.drawable.ic_notes_tag, R.string.notes_tag_wall, primary = false, selected = activeTag != null,
                enabled = !busy, onClick = onTagWall)
        }
    }
}

@Composable
private fun NotesRow(
    entry: NoteSummary,
    enabled: Boolean,
    canOpen: Boolean,
    onOpen: () -> Unit,
    onArchive: () -> Unit,
    onDelete: () -> Unit,
    onConfirmDelete: () -> Unit,
) {
    val archiveLabel = if (entry.archived) R.string.notes_restore else R.string.notes_archive_action
    var menu by remember { mutableStateOf(false) }
    var offset by remember { mutableFloatStateOf(0f) }
    val archiveAction by rememberUpdatedState(onArchive)
    val deleteAction by rememberUpdatedState(onDelete)
    LaunchedEffect(enabled) { if (!enabled) offset = 0f }
    val gesture = if (enabled && !menu) Modifier.pointerInput(entry.id) {
        detectHorizontalDragGestures(
            onDragStart = { offset = 0f },
            onDragCancel = { offset = 0f },
            onDragEnd = {
                val action = notesSwipeAction(offset, size.width)
                offset = 0f
                when (action) {
                    NotesSwipeAction.ARCHIVE -> archiveAction()
                    NotesSwipeAction.DELETE -> deleteAction()
                    null -> Unit
                }
            },
        ) { change, drag ->
            change.consume()
            offset = (offset + drag).coerceIn(-size.width.toFloat(), size.width.toFloat())
        }
    } else Modifier
    Box(Modifier.fillMaxWidth().clipToBounds().then(gesture)) {
        if (offset != 0f) {
            val toArchive = offset > 0f
            val color = if (toArchive) Color(0xFF256849) else Color(0xFF9D2935)
            Row(Modifier.matchParentSize().background(color).padding(horizontal = 14.dp),
                horizontalArrangement = if (toArchive) Arrangement.Start else Arrangement.End,
                verticalAlignment = Alignment.CenterVertically) {
                Icon(painterResource(if (toArchive) R.drawable.ic_notes_archive else R.drawable.ic_notes_delete), null, tint = Color.White)
                Text(stringResource(if (toArchive) archiveLabel else R.string.notes_delete),
                    Modifier.padding(start = 8.dp), color = Color.White)
            }
        }
        Row(Modifier.fillMaxWidth().absoluteOffset { IntOffset(offset.roundToInt(), 0) }
            .background(MaterialTheme.colorScheme.background).heightIn(min = 74.dp),
            verticalAlignment = Alignment.CenterVertically) {
            Row(Modifier.weight(1f).clickable(enabled = enabled && canOpen, role = Role.Button, onClick = onOpen)
                .padding(vertical = 11.dp, horizontal = 5.dp), verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(11.dp)) {
                Box(Modifier.size(38.dp).background(MaterialTheme.colorScheme.primaryContainer, MaterialTheme.shapes.small),
                    contentAlignment = Alignment.Center) {
                    if (entry.icon == null) Icon(painterResource(R.drawable.ic_secure_notes), null, Modifier.size(19.dp),
                        tint = MaterialTheme.colorScheme.onPrimaryContainer)
                    else Text(entry.icon.orEmpty(), style = MaterialTheme.typography.titleMedium, maxLines = 1)
                }
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text(entry.title.ifBlank { stringResource(R.string.notes_untitled) }, style = MaterialTheme.typography.titleMedium,
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                    if (entry.preview.isNotBlank()) Text(entry.preview, style = MaterialTheme.typography.bodyMedium,
                        color = LocalLoftColors.current.secondaryText, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    Text(formatNotesDate(entry.updatedAt), style = MaterialTheme.typography.bodySmall,
                        color = LocalLoftColors.current.secondaryText)
                    if (entry.tags.isNotEmpty()) Text(entry.tags.joinToString("  ") { "#$it" },
                        color = LocalLoftColors.current.link, style = MaterialTheme.typography.bodySmall,
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
            Box {
                NotesIconButton(R.drawable.ic_notes_more, R.string.notes_actions, { menu = true }, enabled = enabled)
                DropdownMenu(menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(text = { Text(stringResource(archiveLabel)) }, onClick = { menu = false; onArchive() })
                    DropdownMenuItem(text = { Text(stringResource(R.string.notes_delete)) },
                        onClick = { menu = false; onConfirmDelete() })
                }
            }
        }
    }
}

@Composable
private fun NotesRoundButton(@DrawableRes icon: Int, @StringRes label: Int, primary: Boolean, selected: Boolean,
    enabled: Boolean, onClick: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    val tint = if (primary) colors.onPrimary else colors.onPrimaryContainer
    Surface(shape = CircleShape, color = if (primary) colors.primary else if (selected) colors.primaryContainer else colors.surfaceVariant) {
        IconButton(onClick = onClick, enabled = enabled, modifier = Modifier.size(if (primary) 64.dp else 52.dp)) {
            Icon(painterResource(icon), stringResource(label), Modifier.size(if (primary) 27.dp else 23.dp),
                tint = if (enabled) tint else tint.copy(alpha = 0.4f))
        }
    }
}

@Composable
internal fun NotesIconButton(@DrawableRes icon: Int, @StringRes label: Int, onClick: () -> Unit, enabled: Boolean = true) {
    IconButton(onClick = onClick, enabled = enabled) { Icon(painterResource(icon), stringResource(label)) }
}

@Composable
internal fun NotesNotice(status: String?, modifier: Modifier = Modifier) {
    if (status == null) return
    Text(stringResource(when (status) {
        "invalid" -> R.string.notes_invalid
        "locked" -> R.string.notes_locked
        "missing" -> R.string.notes_missing
        "conflict" -> R.string.notes_conflict
        "capacity" -> R.string.notes_capacity
        "busy" -> R.string.notes_busy
        else -> R.string.notes_unavailable
    }), modifier.semantics { liveRegion = LiveRegionMode.Polite }, color = MaterialTheme.colorScheme.error,
        style = MaterialTheme.typography.bodyMedium)
}

internal fun formatNotesDate(seconds: ULong): String =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(seconds.toLong() * 1000))
