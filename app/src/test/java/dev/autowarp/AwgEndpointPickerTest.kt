package dev.autowarp

import org.junit.Assert.*
import org.junit.Test
import kotlin.random.Random

class AwgEndpointPickerTest {
    private val quick="""
        [Interface]
        PrivateKey = synthetic-test-key
        Address = 172.16.0.2/32
        I1 = synthetic-signature
        [Peer]
        PublicKey = synthetic-peer-key
        Endpoint = 188.114.96.20:2408
        AllowedIPs = 0.0.0.0/0
    """.trimIndent()

    @Test fun disabledFilterKeepsOriginalAndCustomServersAreNotScanned(){
        assertEquals(listOf(quick),AwgEndpointPicker.candidates(quick,false))
        val custom=AwgEndpointPicker.replace(quick,"203.0.113.1:1234")
        assertEquals(listOf(custom),AwgEndpointPicker.candidates(custom,true))
    }
    @Test fun boundedCandidatesChangeOnlyEndpoint(){
        val choices=AwgEndpointPicker.candidates(quick,true,Random(42))
        assertEquals(8,choices.size)
        assertEquals(quick,choices.first())
        assertEquals(choices.size,choices.toSet().size)
        for(candidate in choices){
            assertEquals(quick,AwgEndpointPicker.replace(candidate,"188.114.96.20:2408"))
        }
        assertTrue(choices.drop(1).all {awgConfiguredEndpoint(it)!!.endsWith(":4500")})
    }
    @Test fun savedEndpointDoesNotReplaceKeysMaskingOrNewerProfile(){
        val masked=AwgEndpointPicker.replace(quick.replace("synthetic-signature","temporary-I1"),"162.159.193.4:4500")
        val saved=AwgEndpointPicker.savedQuick(quick,quick,masked)!!
        assertEquals(AwgEndpointPicker.replace(quick,"162.159.193.4:4500"),saved)
        assertNull(AwgEndpointPicker.savedQuick(quick+"\n#new-import",quick,masked))
        assertNull(AwgEndpointPicker.savedQuick(quick,quick,quick))
    }
    @Test(expected=IllegalArgumentException::class)
    fun ambiguousConfigIsNeverRewritten(){
        AwgEndpointPicker.replace(quick+"\nEndpoint = 188.114.97.1:500","188.114.98.1:4500")
    }
    @Test(expected=IllegalArgumentException::class)
    fun endpointCannotInjectAnotherConfigLine(){
        AwgEndpointPicker.replace(quick,"188.114.98.1:4500\nPrivateKey = bad")
    }
}
