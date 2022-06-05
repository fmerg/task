package main

import (
  "core"
  "fmt"
  "math/big"
)


func demoEcdsa() {

  curve := core.Setup()
  // fmt.Println(core.CryptoParams(curve))

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

func demoPaillier() {

  p := big.NewInt(11)
  q := big.NewInt(17)

  secret := core.NewPaillierKey(p, q)
  public := secret.Public()

  message := big.NewInt(175)
  fmt.Println("message:", message)

  cipher := public.Encrypt(message)
  result := secret.Decrypt(cipher)

  fmt.Println("result:", result)
}


func main() {

  demoEcdsa()
  demoPaillier()
}
