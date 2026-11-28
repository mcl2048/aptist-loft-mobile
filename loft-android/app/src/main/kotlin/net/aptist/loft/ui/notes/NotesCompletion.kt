package net.aptist.loft.ui.notes

internal data class Completion(val start: Int, val end: Int, val replacement: String, val cursor: Int)

private val markdownPairs = mapOf('*' to '*', '_' to '_', '`' to '`', '~' to '~', '[' to ']', '(' to ')')

/** Return an optional edit in post-keystroke coordinates. Pasted text and IME batches are left intact. */
internal fun completeMarkdown(source: String, start: Int, end: Int, inserted: String): Completion? {
    if (start != end || inserted.length != 1) return null
    val typed = inserted.single()
    val preceding = source.getOrNull(start - 1)
    val following = source.getOrNull(start)

    // A space after a leading "*" is a list marker. Remove the empty pair's second asterisk.
    if (typed == ' ' && preceding == '*' && following == '*' &&
        source.substring(source.lastIndexOf('\n', start - 2) + 1, start - 1).isBlank()
    ) return Completion(start, start + 2, " ", start + 1)

    if (typed == following && typed in markdownPairs.values) {
        // **, __, ``` and ~~ grow symmetrically while still empty.
        if (typed == preceding && typed in "*_`~") {
            val before = source.substring(0, start).takeLastWhile { it == typed }.length
            val after = source.substring(start).takeWhile { it == typed }.length
            val maximum = if (typed == '`') 3 else 2
            if (before == after && before < maximum) return Completion(start, start + 1, "$typed$typed", start + 1)
        }
        return Completion(start, start + 1, "", start + 1)
    }
    val closer = markdownPairs[typed] ?: return null
    if (preceding == '\\' || (preceding?.isLetterOrDigit() == true && typed != '(')) return null
    if (typed == '(' && preceding != ']') return null
    return Completion(start, start + 1, "$typed$closer", start + 1)
}
