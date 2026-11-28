package net.aptist.loft.ui.notes

import org.commonmark.ext.gfm.strikethrough.Strikethrough
import org.commonmark.ext.gfm.strikethrough.StrikethroughExtension
import org.commonmark.ext.gfm.tables.TableBlock
import org.commonmark.ext.gfm.tables.TableHead
import org.commonmark.ext.gfm.tables.TableRow
import org.commonmark.ext.gfm.tables.TablesExtension
import org.commonmark.ext.task.list.items.TaskListItemMarker
import org.commonmark.ext.task.list.items.TaskListItemsExtension
import org.commonmark.node.BlockQuote
import org.commonmark.node.BulletList
import org.commonmark.node.Code
import org.commonmark.node.Emphasis
import org.commonmark.node.FencedCodeBlock
import org.commonmark.node.Heading
import org.commonmark.node.Image
import org.commonmark.node.IndentedCodeBlock
import org.commonmark.node.Link
import org.commonmark.node.LinkReferenceDefinition
import org.commonmark.node.ListItem
import org.commonmark.node.Node
import org.commonmark.node.SourceSpan
import org.commonmark.node.StrongEmphasis
import org.commonmark.node.Text
import org.commonmark.node.ThematicBreak
import org.commonmark.parser.IncludeSourceSpans
import org.commonmark.parser.Parser

internal sealed interface NoteFormat {
    data class Heading(val level: Int) : NoteFormat
    data object Strong : NoteFormat
    data object Emphasis : NoteFormat
    data object Strike : NoteFormat
    data object Link : NoteFormat
    data object Quote : NoteFormat
    data object Code : NoteFormat
    data object Table : NoteFormat
}

internal data class MarkdownEdit(val start: Int, val end: Int, val replacement: String)
internal data class MarkdownMark(val start: Int, val end: Int, val format: NoteFormat)

internal data class MarkdownProjection(
    val text: String,
    val edits: List<MarkdownEdit>,
    val marks: List<MarkdownMark>,
)

/**
 * Parse the full document so constructs spanning lines keep their meaning. The projection only
 * changes presentation. Original offsets remain authoritative for selection, clipboard and storage.
 */
internal class NotesMarkdown private constructor(
    private val source: String,
    private val edits: List<MarkdownEdit>,
    private val marks: List<MarkdownMark>,
) {
    fun project(selectionStart: Int? = null, selectionEnd: Int? = null): MarkdownProjection {
        val activeStart = selectionStart?.let { source.lastIndexOf('\n', it - 1) + 1 }
        val activeEnd = selectionEnd?.let { source.indexOf('\n', it).takeUnless { end -> end == -1 } ?: source.length }
        fun rendered(start: Int, end: Int) = activeStart == null || activeEnd == null ||
            end <= activeStart || start >= activeEnd

        val visibleEdits = edits.filter { rendered(it.start, it.end) }
        val adjustment = IntArray(visibleEdits.size + 1)
        val text = buildString(source.length) {
            var cursor = 0
            for ((index, edit) in visibleEdits.withIndex()) {
                append(source, cursor, edit.start)
                append(edit.replacement)
                cursor = edit.end
                adjustment[index + 1] = length - cursor
            }
            append(source, cursor, source.length)
        }
        fun map(offset: Int, inclusiveEnd: Boolean): Int {
            var low = 0
            var high = visibleEdits.size
            while (low < high) {
                val middle = (low + high) / 2
                if (visibleEdits[middle].end <= offset) low = middle + 1 else high = middle
            }
            val edit = visibleEdits.getOrNull(low)
            if (edit != null && offset > edit.start) {
                return edit.start + adjustment[low] + if (inclusiveEnd) edit.replacement.length else 0
            }
            return offset + adjustment[low]
        }
        val visibleMarks = marks.mapNotNull { mark ->
            if (!rendered(mark.start, mark.end)) return@mapNotNull null
            val start = map(mark.start, false)
            val end = map(mark.end, true)
            mark.copy(start = start, end = end).takeIf { start < end }
        }
        return MarkdownProjection(text, visibleEdits, visibleMarks)
    }

    companion object {
        private val parser = Parser.builder()
            .includeSourceSpans(IncludeSourceSpans.BLOCKS_AND_INLINES)
            .extensions(listOf(StrikethroughExtension.create(), TablesExtension.create(), TaskListItemsExtension.create()))
            .maxOpenBlockParsers(40)
            .maxInlineNesting(40)
            .build()

        fun parse(source: String): NotesMarkdown {
            val visitor = ProjectionBuilder(source)
            var node: Node? = parser.parse(source).firstChild
            while (node != null) {
                visitor.visit(node)
                if (node.firstChild != null) {
                    node = node.firstChild
                } else {
                    while (node != null && node.next == null) node = node.parent
                    node = node?.next
                }
            }
            return visitor.build()
        }
    }

    private class ProjectionBuilder(private val source: String) {
        private val edits = mutableListOf<MarkdownEdit>()
        private val marks = mutableListOf<MarkdownMark>()

        fun build(): NotesMarkdown {
            // Child spans may cover source already normalized by a parent (e.g. a task marker).
            // Parent replacements win when overlapping and adjacent replacements remain distinct.
            var end = 0
            val disjoint = edits.sortedWith(compareBy({ it.start }, { -it.end })).filter { edit ->
                (edit.start >= end).also { if (it) end = edit.end }
            }
            return NotesMarkdown(source, disjoint, marks)
        }

        private val SourceSpan.end: Int get() = inputIndex + length

        private fun edit(start: Int, end: Int, replacement: String = "") {
            if (start in 0 until end && end <= source.length && !source.regionMatches(start, replacement, 0, end - start)) {
                edits += MarkdownEdit(start, end, replacement)
            }
        }

        private fun rewrite(span: SourceSpan, replacement: String = "") = edit(span.inputIndex, span.end, replacement)

        private fun format(spans: List<SourceSpan>, format: NoteFormat?) {
            if (format == null) return
            spans.forEach { span -> marks += MarkdownMark(span.inputIndex, span.end, format) }
        }

        private fun inline(node: Node, format: NoteFormat? = null) {
            val spans = node.sourceSpans
            if (spans.isEmpty()) return
            val head = spans.first()
            val tail = spans.last()
            val contentHead = node.firstChild?.sourceSpans?.firstOrNull()
            val contentTail = node.lastChild?.sourceSpans?.lastOrNull()
            if (contentHead == null || contentTail == null) {
                spans.forEach { rewrite(it) }
                return
            }
            if (head.lineIndex == contentHead.lineIndex) edit(head.inputIndex, contentHead.inputIndex)
            if (tail.lineIndex == contentTail.lineIndex) edit(contentTail.end, tail.end)
            format(spans, format)
        }

        fun visit(node: Node) {
            val spans = node.sourceSpans
            val head = spans.firstOrNull() ?: return
            when (node) {
                is Heading -> {
                    // Setext headings have a separate underline row. Leave that newline intact.
                    val headingLines = if (node.firstChild?.sourceSpans?.firstOrNull()?.inputIndex == head.inputIndex && spans.size > 1) {
                        rewrite(spans.last())
                        spans.dropLast(1)
                    } else spans
                    val first = node.firstChild?.sourceSpans?.firstOrNull()
                    val last = node.lastChild?.sourceSpans?.lastOrNull()
                    if (first == null || last == null) headingLines.forEach { rewrite(it) }
                    else {
                        edit(head.inputIndex, first.inputIndex)
                        edit(last.end, headingLines.last().end)
                        format(headingLines, NoteFormat.Heading(node.level))
                    }
                }
                is StrongEmphasis -> inline(node, NoteFormat.Strong)
                is Emphasis -> inline(node, NoteFormat.Emphasis)
                is Strikethrough -> inline(node, NoteFormat.Strike)
                is Link, is Image -> inline(node, NoteFormat.Link)
                is LinkReferenceDefinition -> spans.forEach { rewrite(it) }
                is ThematicBreak -> rewrite(head, "────────")
                is Code -> {
                    if (spans.size == 1) rewrite(head, node.literal)
                    else {
                        val opening = source.substring(head.inputIndex, head.end).takeWhile { it == '`' }.length
                        edit(head.inputIndex, head.inputIndex + opening)
                        edit(spans.last().end - opening, spans.last().end)
                    }
                    format(spans, NoteFormat.Code)
                }
                is FencedCodeBlock -> {
                    rewrite(head)
                    val codeLines = if (node.closingFenceLength != null && spans.size > 1) {
                        rewrite(spans.last())
                        spans.drop(1).dropLast(1)
                    } else spans.drop(1)
                    format(codeLines, NoteFormat.Code)
                }
                is IndentedCodeBlock -> format(spans, NoteFormat.Code)
                is BlockQuote -> {
                    for (span in spans) {
                        val prefix = quotePrefix.find(source.substring(span.inputIndex, span.end)) ?: continue
                        edit(span.inputIndex, span.inputIndex + prefix.value.length, "│ ")
                    }
                    format(spans, NoteFormat.Quote)
                }
                is ListItem -> {
                    val text = source.substring(head.inputIndex, head.end)
                    val marker = bulletPrefix.find(text) ?: return
                    val task = node.firstChild as? TaskListItemMarker
                    // CommonMark's task extension removes the token in the child Text literal.
                    // Keep the whitespace and bracket handling in that node's own source span.
                    if (node.parent is BulletList || task != null) {
                        val symbol = when (task?.isChecked) {
                            true -> "☑ "
                            false -> "☐ "
                            null -> "• "
                        }
                        edit(head.inputIndex, head.inputIndex + marker.value.length, symbol)
                    }
                }
                is TableBlock -> spans.getOrNull(1)?.let { rewrite(it) }
                is TableRow -> {
                    var cell = node.firstChild
                    while (cell?.next != null) {
                        val span = cell.sourceSpans.lastOrNull()
                        if (span != null && span.end < source.length && source[span.end] == '|') {
                            edit(span.end, span.end + 1, "│")
                        }
                        cell = cell.next
                    }
                    val text = source.substring(head.inputIndex, head.end)
                    if (text.startsWith('|')) edit(head.inputIndex, head.inputIndex + 1)
                    if (text.endsWith('|') && !text.endsWith("\\|")) edit(head.end - 1, head.end)
                    format(spans, NoteFormat.Table)
                    if (node.parent is TableHead) format(spans, NoteFormat.Strong)
                }
                is Text -> if (spans.size == 1) rewrite(head, node.literal)
            }
        }

        companion object {
            private val quotePrefix = Regex("^ {0,3}>[ \\t]?")
            private val bulletPrefix = Regex("^ {0,3}(?:[-+*]|[0-9]{1,9}[.)])(?:[ \\t]+|$)")
        }
    }
}
