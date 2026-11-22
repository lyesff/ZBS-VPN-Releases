package dev.autowarp

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.res.imageResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import kotlin.math.roundToInt

/** Exact original concept fragment, decorative and independent of VPN state. */
@Composable internal fun NeonKarateBanner(){
    val image=ImageBitmap.imageResource(R.drawable.zbs_karate_concept)
    // Preserve the supplied source PNG unchanged. Render only its hero artwork;
    // the surrounding mock UI, numbers and unimplemented tabs never appear.
    Canvas(Modifier.fillMaxWidth().aspectRatio(824f/282f).semantics{
        contentDescription="Иллюстрация ZBS VPN: каратист разбивает барьер"
    }){
        drawImage(image,srcOffset=IntOffset(20,164),srcSize=IntSize(824,282),
            dstOffset=IntOffset.Zero,dstSize=IntSize(size.width.roundToInt(),size.height.roundToInt()),
            filterQuality=FilterQuality.Low)
    }
}
