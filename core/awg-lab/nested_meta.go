// SPDX-License-Identifier: GPL-3.0-or-later
package awglab

import (
    "context"
    "crypto/tls"
    "encoding/json"
    "io"
    "net"
    "net/http"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// Match warpscout's metadata source without replacing the original trace.
// Resolution and TCP stay inside the very same stack being measured.
func nestedMeta(parent context.Context,stack *netstack.Net)Result{
    ctx,cancel:=context.WithTimeout(parent,5*time.Second);defer cancel()
    transport:=&http.Transport{
        DisableKeepAlives:true,
        TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12},
        DialContext:func(c context.Context,_,_ string)(net.Conn,error){
            return stack.DialContext(c,"tcp4","speed.cloudflare.com:443")
        },
    }
    defer transport.CloseIdleConnections()
    client:=&http.Client{Transport:transport,
        CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
    req,err:=http.NewRequestWithContext(ctx,http.MethodGet,"https://speed.cloudflare.com/meta",nil)
    if err!=nil{return Result{}}
    req.Header.Set("Referer","https://speed.cloudflare.com")
    req.Header.Set("Accept","application/json")
    response,err:=client.Do(req);if err!=nil{return Result{}}
    defer response.Body.Close()
    if response.StatusCode!=http.StatusOK{return Result{}}
    body,err:=io.ReadAll(io.LimitReader(response.Body,8193))
    if err!=nil{return Result{}}
    return parseNestedMeta(body)
}

func parseNestedMeta(body []byte)Result{
    if len(body)==0 || len(body)>8192{return Result{}}
    var data struct{
        Country string `json:"country"`
        Colo struct{IATA string `json:"iata"`} `json:"colo"`
    }
    if json.Unmarshal(body,&data)!=nil{return Result{}}
    country,colo:=traceCountryCode(data.Country),traceColoCode(data.Colo.IATA)
    if country=="" || colo==""{return Result{}}
    return Result{Verified:true,Country:country,Colo:colo}
}

func nestedCountryDisagrees(trace,meta Result)bool{
    return trace.Verified && meta.Verified && trace.Country!="" && meta.Country!="" && trace.Country!=meta.Country
}
