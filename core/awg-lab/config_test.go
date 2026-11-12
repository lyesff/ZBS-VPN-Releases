package awglab

import (
  "encoding/base64"
  "strings"
  "testing"
)

func TestQuickConfigRetainsAWGObfuscation(t *testing.T){
   key:=base64.StdEncoding.EncodeToString([]byte(strings.Repeat("A",32)))
   file:="[Interface]\nPrivateKey = "+key+"\nAddress = 172.16.0.2/32, 2606:4700:110:8765::2/128\n"+
     "Jc = 4\nJmin = 40\nJmax = 70\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n"+
     "I1 = <b 0xaabbccdd>\nRandomTrailers = on\nDisableCookies = on\n"+
     "[Peer]\nPublicKey = "+key+"\nAllowedIPs = 0.0.0.0/0, ::/0\n"+
     "Endpoint = 162.159.193.1:4500\nPersistentKeepalive = 25\n"
   cfg,err:=FromQuickConfig(file)
   if err!=nil{t.Fatal(err)}
   if cfg.LocalIPv4!="172.16.0.2"{t.Fatalf("incorrect interface address")}
   for _,s:=range []string{"jc=4","jmin=40","jmax=70","h1=1","h4=4",
      "i1=<b 0xaabbccdd>","random_trailers=true","disable_cookies=true",
      "endpoint=162.159.193.1:4500","allowed_ip=0.0.0.0/0"}{
      if !strings.Contains(cfg.IPCSettings,s){t.Fatalf("missing UAPI key %s",s)}
   }
   if strings.Contains(cfg.IPCSettings,key){t.Fatal("raw base64 key exposed in UAPI")}
}
func TestQuickConfigRejectsUnexpectedFields(t *testing.T){
   key:=base64.StdEncoding.EncodeToString([]byte(strings.Repeat("A",32)))
   good:="[Interface]\nPrivateKey = "+key+"\nAddress = 172.16.0.2/32\n[Peer]\nPublicKey = "+key+
      "\nAllowedIPs = 0.0.0.0/0\nEndpoint = engage.cloudflareclient.com:4500\n"
   for _,mutated:=range []string{
     strings.Replace(good,"Address = ","Address = garbage, ",1),
     strings.Replace(good,"PrivateKey = ","SecretKey = ",1),
     strings.Replace(good,"4500","0",1),
     strings.Replace(good,"0.0.0.0/0","invalid",1),
     good+"I6 = bad\n",
   }{
      if _,err:=FromQuickConfig(mutated);err==nil{t.Fatal("accepted invalid file")}
   }
}
