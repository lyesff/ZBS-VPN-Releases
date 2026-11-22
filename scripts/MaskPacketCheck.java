package dev.autowarp;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Standalone JVM checks; also run in the diagnostic APK workflow. */
public final class MaskPacketCheck {
    private static void check(boolean value, String why) { if (!value) throw new AssertionError(why); }
    private static int u16(byte[] b, int p) { return (b[p]&255)*256+(b[p+1]&255); }
    private static boolean contains(byte[] b, String s) {
        return new String(b, StandardCharsets.ISO_8859_1).contains(s);
    }
    public static void main(String[] args) throws Exception {
        // RFC 9001 Appendix A.1 client Initial key derivation vector.
        byte[][] keys=AwgMaskPackets.initialKeys(AwgMaskPackets.unhex("8394c8f03e515708"));
        check(AwgMaskPackets.hex(keys[0]).equals("1f369613dd76d5467730efcbe3b1a22d"),"RFC key");
        check(AwgMaskPackets.hex(keys[1]).equals("fa044b2f42a3fd3b46fb255c"),"RFC IV");
        check(AwgMaskPackets.hex(keys[2]).equals("9f50449e04a0e810283a1e9933adedd2"),"RFC HP");
        for(int run=0;run<64;run++) {
            byte[] packet=AwgMaskPackets.quic();
            check(packet.length==1200,"QUIC minimum datagram");
            check(u16(packet,3)==1 && packet[5]==8 && packet[14]==8 && packet[23]==0,"QUIC v1 CID/token");
            int length=((packet[24]&63)<<8)|(packet[25]&255);
            check(length==packet.length-26,"QUIC Length covers PN and AEAD");
            byte[][] k=AwgMaskPackets.initialKeys(Arrays.copyOfRange(packet,6,14));
            Cipher hp=Cipher.getInstance("AES/ECB/NoPadding");
            hp.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(k[2],"AES"));
            byte[] mask=hp.doFinal(Arrays.copyOfRange(packet,30,46));
            byte[] header=Arrays.copyOf(packet,30);
            header[0]^=mask[0]&15;
            check((header[0]&255)==0xc3,"Initial type and four-byte PN");
            for(int j=0;j<4;j++) {header[26+j]^=mask[1+j];check(header[26+j]==0,"packet number zero");}
            Cipher aead=Cipher.getInstance("AES/GCM/NoPadding");
            aead.init(Cipher.DECRYPT_MODE,new SecretKeySpec(k[0],"AES"),new GCMParameterSpec(128,k[1]));
            aead.updateAAD(header);
            byte[] plain=aead.doFinal(Arrays.copyOfRange(packet,30,packet.length));
            check(plain[0]==6 && plain[1]==0,"CRYPTO frame at offset zero");
            int n=((plain[2]&63)<<8)|(plain[3]&255);
            check(n>64 && n+4<plain.length,"complete ClientHello frame");
            check(plain[4]==1,"TLS ClientHello");
            int helloLength=((plain[5]&255)<<16)|((plain[6]&255)<<8)|(plain[7]&255);
            check(helloLength+4==n,"TLS handshake length");
            check(contains(plain,"www.apple.com") && contains(plain,"h3"),"SNI and ALPN survive authentication");
            for(int j=4+n;j<plain.length;j++)check(plain[j]==0,"QUIC PADDING");
            byte[] dns=AwgMaskPackets.dns();
            check(u16(dns,2)==0x100 && u16(dns,4)==1 && u16(dns,10)==1,"DNS A query with OPT");
            int p=12;while(dns[p]!=0)p+=1+(dns[p]&255);p+=5;
            check(dns[p]==0 && u16(dns,p+1)==41,"EDNS OPT record");
            int rdlen=u16(dns,p+9), pad=u16(dns,p+13);
            check(u16(dns,p+11)==12 && rdlen==4+pad && p+11+rdlen==dns.length,"EDNS padding framing");
            byte[] stun=AwgMaskPackets.stun();
            check(u16(stun,0)==1 && u16(stun,2)==stun.length-20,"STUN Binding Request length");
            check(AwgMaskPackets.hex(Arrays.copyOfRange(stun,4,8)).equals("2112a442"),"STUN cookie");
            check(u16(stun,20)==0x8022 && (stun.length-20)%4==0,"STUN padded SOFTWARE attribute");
        }
        for(String mode:new String[]{"quic","dns","stun"}) {
            String a=AwgMaskPackets.signature(mode), b=AwgMaskPackets.signature(mode);
            check(a.matches("<b 0x(?:[0-9a-f]{2}){1,2048}>"),"bounded supported CPS: "+mode);
            check(!a.equals(b),"fresh entropy per connection: "+mode);
        }
        try {AwgMaskPackets.signature("unknown");throw new AssertionError("unknown mode accepted");}
        catch(IllegalArgumentException expected) {}
        System.out.println("PASS: RFC key vector; 64 authenticated QUIC/TLS, DNS/EDNS and STUN packets; CPS bounds and freshness.");
    }
}
