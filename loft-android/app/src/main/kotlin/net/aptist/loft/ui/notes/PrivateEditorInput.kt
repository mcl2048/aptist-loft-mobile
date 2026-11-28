@file:OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)

package net.aptist.loft.ui.notes

import android.view.inputmethod.EditorInfo
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.InterceptPlatformTextInput
import androidx.compose.ui.platform.PlatformTextInputInterceptor

private val privateInput = PlatformTextInputInterceptor { request, next ->
    next.startInputMethod { info ->
        request.createInputConnection(info).also {
            info.imeOptions = info.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        }
    }
}

/** Private fields remain editable without allowing supporting keyboards to learn from them. */
@Composable
internal fun PrivateEditorInput(content: @Composable () -> Unit) {
    InterceptPlatformTextInput(privateInput, content)
}
