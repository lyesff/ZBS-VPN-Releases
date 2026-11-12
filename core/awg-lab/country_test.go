package awglab

import "testing"

func TestTraceCountryCodeExportsOnlyBoundedMetadata(t *testing.T){
    for raw,want:=range map[string]string{
        "RU":"RU"," de ":"DE","us":"US","":"", "XX":"", "ZZ":"",
        "RUS":"", "R1":"", "synthetic-secret":"", "RU\nprivate_key=synthetic":"",
    }{
        if traceCountryCode(raw)!=want{t.Fatal("country normalization accepted invalid metadata")}
    }
    var absent *AndroidVPNPreparation
    if absent.CountryCode()!=""{t.Fatal("missing preparation claimed a country")}
    p:=&AndroidVPNPreparation{country:"DE"}
    if p.CountryCode()!="DE"{t.Fatal("preparation country not exposed")}
    p.closed=true
    if p.CountryCode()!=""{t.Fatal("closed preparation exposed a stale country")}
}
