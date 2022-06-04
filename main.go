package main

import (
  "core"
  "fmt"
)


func demoFlow() {

  curve := core.Setup()
  key, public := core.KeyGen(curve)

  message := "to-be-signed"
  var verified bool

  // low level version
  r, s := core.Sign(message, key)
  verified = core.VerifySignature(message, &public, r, s)
  fmt.Println(verified)

  // ASN.1 version
  signature := core.SignASN1(message, key)
  verified = core.VerifySignatureASN1(message, &public, signature)
  fmt.Println(verified)
}


func main() {

  demoFlow()
}
