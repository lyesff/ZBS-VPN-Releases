//go:build linux

package awglab

import (
    "errors"
    "testing"
)

type failingTrafficWrite struct{*handoffFixture}
func (f *failingTrafficWrite) Write(_ [][]byte,_ int)(int,error){
    return 0,errors.New("synthetic write failure")
}

func TestTrafficBytesUseIPLengthsAndCorrectDirections(t *testing.T){
    native:=newHandoffFixture(true)
    defer native.Close()
    stats:=fixtureStats()
    counted:=&countingTun{Device:native,stats:stats}
    engine:=&AndroidVPN{stats:stats}
    upload:=[]byte{0x45,1,2,3,4,5,6}
    native.input<-upload
    sizes:=make([]int,1)
    if n,err:=counted.Read([][]byte{make([]byte,128)},sizes,16);err!=nil || n!=1{
        t.Fatal("fixture read failed")
    }
    if engine.TrafficBytes()!="0,7"{t.Fatal("upload included headroom or used wrong direction")}
    download:=[]byte{0x45,1,2,3,4,5,6,7,8,9,10}
    packet:=append(make([]byte,16),download...)
    if n,err:=counted.Write([][]byte{packet},16);err!=nil || n!=1{
        t.Fatal("fixture write failed")
    }
    if engine.TrafficBytes()!="11,7"{t.Fatal("download counted packets/offset instead of IP bytes")}
    failed:=&countingTun{Device:&failingTrafficWrite{newHandoffFixture(true)},stats:stats}
    defer failed.Close()
    if _,err:=failed.Write([][]byte{packet},16);err==nil{t.Fatal("fixture did not reject write")}
    if engine.TrafficBytes()!="11,7"{t.Fatal("failed TUN write inflated download")}
    if (&AndroidVPN{}).TrafficBytes()!="0,0"{t.Fatal("empty engine did not return zero totals")}
}

func TestTrafficBytesExcludePreflightAndOuterUDP(t *testing.T){
    initial,native:=newHandoffFixture(false),newHandoffFixture(true)
    stats:=fixtureStats()
    engine:=&AndroidVPN{stats:stats}
    handoff:=newHandoffTun(initial,stats)
    defer handoff.Close()
    if _,err:=handoff.Write([][]byte{[]byte{0x45,1,2,3}},0);err!=nil{
        t.Fatal("preflight write failed")
    }
    stats.recordUDP(true,false);stats.recordUDP(false,false)
    if engine.TrafficBytes()!="0,0"{t.Fatal("preflight or outer UDP inflated user traffic")}
    if err:=handoff.attach(native);err!=nil{t.Fatal("handoff failed")}
    stats.recordUDP(true,false);stats.recordUDP(false,false)
    if engine.TrafficBytes()!="0,0"{t.Fatal("masking/keepalive UDP inflated IP traffic")}
}
