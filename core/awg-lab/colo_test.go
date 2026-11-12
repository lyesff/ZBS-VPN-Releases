package awglab

import "testing"

func TestTraceColoMetadataIsSeparateFromCountry(t *testing.T){
    for raw,want:=range map[string]string{
        "HEL":"HEL"," fra ":"FRA","DME":"DME","RU":"","":"",
        "H3L":"","HEL\nprivate_key=synthetic":"","synthetic-secret":"",
    }{
        if traceColoCode(raw)!=want{t.Fatal("invalid colo metadata handling")}
    }
    var absent *AndroidVPNPreparation
    if absent.ColoCode()!=""{t.Fatal("missing preparation exposed colo")}
    p:=&AndroidVPNPreparation{country:"RU",colo:"HEL"}
    if p.CountryCode()!="RU" || p.ColoCode()!="HEL"{t.Fatal("colo and loc were conflated")}
    p.closed=true
    if p.ColoCode()!=""{t.Fatal("closed preparation exposed stale colo")}
}
