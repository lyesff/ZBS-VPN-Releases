package dev.autowarp

import org.junit.Assert.*
import org.junit.Test

class AwgMaskingTest {
    private val original="""[Interface]
# keep this comment
PrivateKey = synthetic-private
Address = 172.16.0.2/32
S1 = 0
H1 = 1
RandomTrailers = on

[Peer]
PublicKey = synthetic-public
Endpoint = 162.159.193.1:2408
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    private val signature="<b 0xce00000001>"

    @Test fun generatedSignaturesKeepEveryOtherConfigFieldUnchanged(){
        for(mode in listOf("quic","dns","stun")){
            val signature=AwgMaskPackets.signature(mode)
            val changed=AwgMasking.withI1(original,signature)
            assertEquals(original,changed.replace("I1 = $signature\n",""))
            assertEquals(original.substringAfter("[Peer]"),changed.substringAfter("[Peer]"))
        }
    }
    @Test fun addsOnlyI1AndKeepsIdentityEndpointAndProtocolFields(){
        val changed=AwgMasking.withI1(original,signature)
        assertEquals(original,changed.replace("I1 = $signature\n",""))
        assertEquals(1,Regex("(?m)^I1 = ").findAll(changed).count())
    }
    @Test fun replacesExistingI1WithoutAccumulatingPacketsOrChangingI2(){
        val old=original.replace("[Interface]\n","[Interface]\nI1 = <b 0x0102>\nI2 = <r 20>\n")
        val changed=AwgMasking.withI1(old,signature)
        assertEquals(1,Regex("(?m)^I1 = ").findAll(changed).count())
        assertTrue(changed.contains("I2 = <r 20>"))
        assertEquals(changed,AwgMasking.withI1(changed,signature))
        assertEquals(old.substringAfter("[Peer]"),changed.substringAfter("[Peer]"))
    }
    @Test fun acceptsWindowsLineEndingsWithoutChangingFieldValues(){
        val changed=AwgMasking.withI1(original.replace("\n","\r\n"),signature)
        assertEquals(original,changed.replace("I1 = $signature\n",""))
    }
    @Test fun rejectsInvalidSignatureInsteadOfInjectingConfigFields(){
        for(value in listOf("<b 0x0>","<b 0xzz>","<b 0x00>\nEndpoint = unsafe","<r 20>")){
            try {AwgMasking.withI1(original,value);fail("Invalid CPS accepted")}
            catch(_:IllegalArgumentException){}
        }
    }
    @Test fun rejectsDuplicateInterfaceOrDuplicateI1(){
        for(value in listOf(original+"[Interface]\n",original.replace("[Interface]\n",
            "[Interface]\nI1 = <b 0x00>\nI1 = <b 0x01>\n"))){
            try {AwgMasking.withI1(value,signature);fail("Duplicate accepted")}
            catch(_:IllegalArgumentException){}
        }
    }
}
