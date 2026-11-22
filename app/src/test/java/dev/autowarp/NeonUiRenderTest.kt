package dev.autowarp

import android.graphics.Bitmap
import android.graphics.Canvas
import android.view.View
import android.app.Activity
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

/** Render production components without loading a VPN engine or starting a tunnel. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk=[34],qualifiers="w393dp-h852dp-mdpi")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@OptIn(ExperimentalTestApi::class)
class NeonUiRenderTest {
    @get:Rule val compose=createAndroidComposeRule<ComponentActivity>()

    private fun render(live:Live,button:String,enabled:Boolean=true,fontScale:Float=1f,onClick:()->Unit={}){
        compose.setContent{
            CompositionLocalProvider(LocalDensity provides Density(1f,fontScale)){
                NeonTheme{
                    Scaffold(bottomBar={NeonNavigationBar(0){}}){padding->
                        Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState())
                            .padding(20.dp),verticalArrangement=Arrangement.spacedBy(12.dp)){
                            NeonBrand()
                            ConnectionOverview(live,true,true,757_000L,"awg_vpn_transport_preflight_start")
                            NeonConnectButton(button,enabled,onClick)
                            NeonControlRow("Маскировка","Авто",enabled=!live.running){}
                            NeonControlRow("DNS (DoH)","Cloudflare",subtitle="Защищённый DNS и обход геоблокировок",glyph=NeonGlyph.GLOBE){}
                            NeonStatusStrip(live.phase==Phase.CONNECTED)
                            Text("Подключение с маскировкой использует IPv4. IPv6 блокируется.")
                        }
                    }
                }
            }
        }
        compose.waitForIdle()
    }
    private fun screenshot(name:String){
        // PixelCopy's forceRedraw waits for a real RenderThread callback in
        // this Compose version. Draw the native-graphics View on the UI thread
        // instead, retaining the same laid-out production components.
        compose.runOnIdle{writeNeonPreview(compose.activity,name)}
    }
    @Test fun connectedScreenRendersRealMetricsAndKeepsDisconnectClickable(){
        var clicks=0
        render(Live(Phase.CONNECTED,Reason.ONLINE,"AmneziaWG · Android","WARP",
            "198.51.100.42",42,1_000L,up=753_664,down=2_516_582,country="RU"),"Отключить",onClick={clicks++})
        compose.onNodeWithText("42 мс").assertExists()
        compose.onNodeWithText("00:12:36").assertExists()
        compose.onNodeWithText("Отключить").assertIsEnabled().performClick()
        assertEquals(1,clicks)
        screenshot("connected")
    }
    @Test fun connectingScreenOffersCancelWithoutAnOnlineBadge(){
        render(Live(Phase.CONNECTING,Reason.VERIFY),"Отменить подключение")
        compose.onNodeWithText("Отменить подключение").assertIsEnabled()
        compose.onNodeWithText("WARP ПОДТВЕРЖДЁН · ВСЁ ZBS!").assertDoesNotExist()
        screenshot("connecting")
    }
    @Test @Config(qualifiers="w320dp-h740dp-mdpi")
    fun smallScreenWithLargeTextCanScrollToControlsWithoutEnablingStoppingButton(){
        render(Live(Phase.DISCONNECTING,Reason.STOP),"Отключение…",enabled=false,fontScale=1.3f)
        compose.onNodeWithText("Отключение…").performScrollTo().assertIsNotEnabled()
        screenshot("small-large-text")
    }
}

internal fun writeNeonPreview(activity:Activity,name:String){
    val directory=File(requireNotNull(System.getProperty("neon.screenshotDir")))
    directory.mkdirs()
    val view=activity.findViewById<View>(android.R.id.content)
    check(view.width>0 && view.height>0)
    val bitmap=Bitmap.createBitmap(view.width,view.height,Bitmap.Config.ARGB_8888)
    view.draw(Canvas(bitmap))
    File(directory,"$name.png").outputStream().use{check(bitmap.compress(Bitmap.CompressFormat.PNG,100,it))}
}
