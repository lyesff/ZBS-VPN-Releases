package awglab

import (
    "strings"
    "testing"
)

func TestNestedMetaKeepsExitCountrySeparateFromNodeCountry(t *testing.T){
    got:=parseNestedMeta([]byte(`{"country":"RU","colo":{"iata":"HEL","cca2":"FI","city":"Helsinki"}}`))
    if !got.Verified || got.Country!="RU" || got.Colo!="HEL"{t.Fatal("metadata country confused with node country")}
    got=parseNestedMeta([]byte(`{"country":"DE","colo":{"iata":"HEL","cca2":"FI"}}`))
    if got.Country!="DE"{t.Fatal("exit country not preserved")}
}

func TestNestedMetaRejectsMalformedOrUnboundedMetadata(t *testing.T){
    for _,body:=range []string{"", "not-json", `{"country":"RU"}`, `{"country":"XX","colo":{"iata":"HEL"}}`,
        `{"country":"RU","colo":{"iata":"HEL\nsynthetic-secret"}}`,strings.Repeat(" ",8193)}{
        if parseNestedMeta([]byte(body)).Verified{t.Fatal("invalid metadata accepted")}
    }
}

func TestNestedCountryDisagreementCannotBecomeForeignSuccess(t *testing.T){
    ru:=Result{Verified:true,Country:"RU",Colo:"HEL"}
    de:=Result{Verified:true,Country:"DE",Colo:"HEL"}
    if !nestedCountryDisagrees(ru,de) || !nestedCountryDisagrees(de,ru){t.Fatal("country disagreement lost")}
    if nestedCountryDisagrees(ru,ru) || nestedCountryDisagrees(ru,Result{}){t.Fatal("invented country disagreement")}
}
