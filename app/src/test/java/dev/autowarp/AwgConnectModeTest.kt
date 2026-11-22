package dev.autowarp

import org.junit.Assert.*
import org.junit.Test

class AwgConnectModeTest {
    @Test fun manualChoiceNeverFallsBackEvenWhenAnotherMaskWasSuccessful(){
        for(mode in AwgConnectMode.entries.filter{it!=AwgConnectMode.AUTO}){
            assertEquals(listOf(mode),AwgConnectMode.plan(mode,true,"dns"))
            assertEquals(listOf(mode),AwgConnectMode.plan(mode,false,"stun"))
        }
    }
    @Test fun autoTriesVerifiedMaskFirstWithoutRepeatingIt(){
        val plan=AwgConnectMode.plan(AwgConnectMode.AUTO,false,"dns")
        assertEquals(AwgConnectMode.DNS,plan.first())
        assertEquals(5,plan.size)
        assertEquals(plan.size,plan.distinct().size)
        assertFalse(plan.contains(AwgConnectMode.AUTO))
        assertEquals(AwgConnectMode.entries.filter{it!=AwgConnectMode.AUTO}.toSet(),plan.toSet())
    }
    @Test fun freshImportUsesItsOwnMaskBeforeChangingI1(){
        assertEquals(AwgConnectMode.PROFILE,AwgConnectMode.plan(AwgConnectMode.AUTO,true,"").first())
        assertEquals(AwgConnectMode.I1,AwgConnectMode.plan(AwgConnectMode.AUTO,false,"").first())
    }
    @Test fun invalidSavedValuesCannotBecomeAnAttempt(){
        for(value in listOf("","auto","obsolete")){
            assertEquals(AwgConnectMode.I1,AwgConnectMode.plan(AwgConnectMode.AUTO,false,value).first())
        }
        assertEquals(AwgConnectMode.AUTO,AwgConnectMode.selected("obsolete"))
        assertEquals(AwgConnectMode.AUTO,AwgConnectMode.selected(""))
    }
}
