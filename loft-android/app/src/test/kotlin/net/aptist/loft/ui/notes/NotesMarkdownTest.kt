package net.aptist.loft.ui.notes

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NotesMarkdownTest {
    @Test
    fun movingTheCaretRevealsOnlyItsSourceLine() {
        val source = "# Plan\n*Hello GPT*\n**Today**"
        val document = NotesMarkdown.parse(source)
        assertEquals("Plan\nHello GPT\nToday", document.project().text)
        val active = document.project(source.indexOf("GPT"), source.indexOf("GPT"))
        assertEquals("Plan\n*Hello GPT*\nToday", active.text)
        assertEquals(setOf(NoteFormat.Heading(1), NoteFormat.Strong), active.marks.map { it.format }.toSet())
        assertEquals(source, document.project(0, source.length).text)
    }

    @Test
    fun mainMarkdownStructuresRenderWithoutExecutableContent() {
        val source = listOf(
            "> **Strong _nested_**",
            "",
            "- [x] Done",
            "- Item",
            "",
            "[Link](https://example.invalid) and ![Chart](https://example.invalid/chart.png)",
            "",
            "~~Archived~~ and " + '`' + "code" + '`',
            "",
            "X | Y",
            "--- | ---",
            "a | b",
            "",
            "<script>alert(1)</script>",
        ).joinToString("\n")
        val rendered = NotesMarkdown.parse(source).project()
        assertTrue(rendered.text.startsWith("│ Strong nested\n\n☑ Done\n• Item"))
        assertTrue(rendered.text.contains("Link and Chart"))
        assertTrue(rendered.text.contains("X │ Y\n\na │ b"))
        assertTrue(rendered.text.contains("<script>alert(1)</script>"))
        assertTrue(rendered.marks.any { it.format == NoteFormat.Emphasis })
        assertTrue(rendered.marks.any { it.format == NoteFormat.Strike })
        assertTrue(rendered.marks.any { it.format == NoteFormat.Code })
    }

    @Test
    fun pairingUsesNaturalClosingKeystrokeAndDoesNotAlterPastedText() {
        assertEquals(Completion(0, 1, "**", 1), completeMarkdown("", 0, 0, "*"))
        assertEquals(Completion(1, 2, "**", 2), completeMarkdown("**", 1, 1, "*"))
        assertEquals(Completion(6, 7, "", 7), completeMarkdown("*hello*", 6, 6, "*"))
        assertEquals(Completion(1, 3, " ", 2), completeMarkdown("**", 1, 1, " "))
        assertNull(completeMarkdown("", 0, 0, "*paste*"))
        assertNull(completeMarkdown("path", 2, 2, "_"))
        assertNull(completeMarkdown("\\", 1, 1, "*"))
    }

    @Test
    fun outputEditsAndStylesLeaveValidCoordinatesThroughUnicodeAndCrLf() {
        val source = "### 🔐 Plan\r\n*日本語* and &amp; _ä_"
        val projection = NotesMarkdown.parse(source).project()
        assertEquals("🔐 Plan\r\n日本語 and & ä", projection.text)
        for (mark in projection.marks) {
            assertTrue(mark.start in 0 until mark.end)
            assertTrue(mark.end <= projection.text.length)
        }
        val japanese = projection.marks.first { it.format == NoteFormat.Emphasis }
        assertEquals("日本語", projection.text.substring(japanese.start, japanese.end))
    }

    @Test
    fun inlineCodeAndEscapedCharactersPreserveContent() {
        val fence = "```"
        val source = "$fence kotlin\nval pair = \"**literal**\"\n$fence\n\\*asterisk\\* &amp;"
        val projection = NotesMarkdown.parse(source).project()
        assertEquals("\nval pair = \"**literal**\"\n\n*asterisk* &", projection.text)
        assertTrue(projection.marks.any { it.format == NoteFormat.Code })
    }

    @Test
    fun tagWallSpreadsFromTheCenterAndItsSettledCellsNeverOverlap() {
        val width = 272f
        val count = 20
        val settled = noteTagWall(width, count, 1f)
        assertEquals(count, settled.items.size)
        assertTrue(settled.items.all { it.x >= 0f && it.x + settled.chipWidth <= width })
        for ((index, a) in settled.items.withIndex()) for (b in settled.items.drop(index + 1)) {
            assertTrue(kotlin.math.abs(a.x - b.x) >= settled.chipWidth ||
                kotlin.math.abs(a.y - b.y) >= NOTE_TAG_CHIP_HEIGHT)
        }
        val start = noteTagWall(width, count, 0f)
        assertTrue(start.items.all { it == start.items.first() })
    }

    @Test
    fun archiveAndDeleteRequireMostOfTheVisibleRowToBeDragged() {
        assertNull(notesSwipeAction(49f, 100))
        assertNull(notesSwipeAction(-59f, 100))
        assertNull(notesSwipeAction(0f, 0))
        assertEquals(NotesSwipeAction.ARCHIVE, notesSwipeAction(60f, 100))
        assertEquals(NotesSwipeAction.DELETE, notesSwipeAction(-60f, 100))
    }
}
