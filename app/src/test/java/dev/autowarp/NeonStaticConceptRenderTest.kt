package dev.autowarp

import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import org.junit.Assert.assertTrue
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.unit.dp
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@Config(sdk=[34],qualifiers="w393dp-h852dp-mdpi")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class NeonStaticConceptRenderTest {
    @get:Rule val compose=createAndroidComposeRule<ComponentActivity>()
    private fun render(phase:State<Phase>){
        compose.setContent{
            NeonTheme{
                Scaffold(bottomBar={NeonNavigationBar(0){}}){padding->
                    Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(20.dp),
                        verticalArrangement=Arrangement.spacedBy(12.dp)){
                        NeonBrand()
                        NeonKarateBanner()
                        val connected=phase.value==Phase.CONNECTED
                        val live=if(connected)Live(Phase.CONNECTED,Reason.ONLINE,"AmneziaWG · Android","WARP",
                            "198.51.100.42",42,1_000L,up=753_664,down=2_516_582,country="RU") else Live(phase.value)
                        Box(Modifier.testTag("compact-info")){ConnectionOverview(live,true,true,757_000L,"")}
                        NeonConnectButton(if(connected)"Отключить" else "Подключить с маскировкой",true){}
                        NeonControlRow("Маскировка","Авто"){}
                    }
                }
            }
        }
        compose.waitForIdle()
    }
    private fun save(name:String)=compose.runOnIdle{writeNeonPreview(compose.activity,name)}

    @Test fun staticConceptIsPresentInEveryVpnState(){
        val phase=mutableStateOf(Phase.DISCONNECTED)
        render(phase)
        compose.onNodeWithContentDescription("Иллюстрация ZBS VPN: каратист разбивает барьер").assertExists()
        save("concept-idle")
        for(value in listOf(Phase.CONNECTING,Phase.ERROR,Phase.CONNECTED,Phase.DISCONNECTING)){
            compose.runOnIdle{phase.value=value}
            compose.onNodeWithContentDescription("Иллюстрация ZBS VPN: каратист разбивает барьер").assertExists()
        }
    }
    @Test fun compactPanelRetainsMetricsAndLeavesTheMainButtonVisible(){
        render(mutableStateOf(Phase.CONNECTED))
        compose.onNodeWithText("42 мс").assertExists()
        compose.onNodeWithText("00:12:36").assertExists()
        compose.onNodeWithText("Внешний IP · 198.51.100.42").assertExists()
        val height=compose.onNodeWithTag("compact-info").fetchSemanticsNode().boundsInRoot.height
        assertTrue("Connected info panel must be at most 240dp at mdpi, was $height",height<=240f)
        compose.onNodeWithText("Отключить").assertIsDisplayed()
        save("concept-connected")
    }
    @Test fun profileAndSettingsPanelsUseTheNeonCardStyle(){
        compose.setContent{
            NeonTheme{
                Scaffold(bottomBar={NeonNavigationBar(3){}}){padding->
                    Column(Modifier.fillMaxSize().padding(padding).padding(20.dp),verticalArrangement=Arrangement.spacedBy(18.dp)){
                        Text("Профиль",style=MaterialTheme.typography.headlineLarge)
                        NeonCard(Modifier.fillMaxWidth()){
                            Column(Modifier.padding(20.dp),verticalArrangement=Arrangement.spacedBy(12.dp)){
                                Text("Профиль готов",style=MaterialTheme.typography.titleLarge)
                                Text("Профиль сохранён на этом устройстве и готов к подключению.")
                                OutlinedButton(onClick={},modifier=Modifier.fillMaxWidth()){Text("Импортировать другой профиль")}
                            }
                        }
                        Text("Настройки",style=MaterialTheme.typography.headlineLarge)
                        NeonControlRow("DNS (DoH)","Cloudflare",glyph=NeonGlyph.GLOBE){}
                        NeonCard(Modifier.fillMaxWidth()){
                            Column(Modifier.padding(20.dp),verticalArrangement=Arrangement.spacedBy(8.dp)){
                                Text("Подключение с маскировкой",style=MaterialTheme.typography.titleMedium)
                                Text("Интернет через WARP. Сейчас поддерживается IPv4, IPv6 блокируется.")
                            }
                        }
                    }
                }
            }
        }
        compose.waitForIdle();save("neon-menus")
    }
}
