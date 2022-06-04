package core

import (
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/sha256"
  "crypto/rand"
  "math/big"
  "hash"
  "fmt"
  "log"
  "io"
)


func Hash(text string) []byte {

  var h hash.Hash
  h = sha256.New()
  io.WriteString(h, text)

  return h.Sum(nil)
}


func Setup() elliptic.Curve {
  return elliptic.P256()
}


func KeyGen(curve elliptic.Curve) (*ecdsa.PrivateKey, ecdsa.PublicKey) {

  key, err := ecdsa.GenerateKey(curve, rand.Reader)

  if err != nil {
    log.Fatal(err)
  }

  return key, key.PublicKey
}


func SignMessage(text string, key *ecdsa.PrivateKey) (*big.Int, *big.Int) {

  r, s, err := ecdsa.Sign(rand.Reader, key, Hash(text))

  if err != nil {
    log.Fatal(err)
  }

  return r, s
}


func VerifySignature(text string, public *ecdsa.PublicKey, r, s *big.Int) bool {

  return ecdsa.Verify(public, Hash(text), r, s)
}


func SignMessageASN1(text string, key *ecdsa.PrivateKey) []byte {

  signature, err := ecdsa.SignASN1(rand.Reader, key, Hash(text))

  if err != nil {
    log.Fatal(err)
  }

  return signature
}


func VerifySignatureASN1(text string, public *ecdsa.PublicKey, signature []byte) bool {

  return ecdsa.VerifyASN1(public, Hash(text), signature)
}


func DemoFlow() {

  curve := Setup()
  key, public := KeyGen(curve)

  message := "to-be-signed"

  // low level version
  r, s := SignMessage(message, key)
  vrf1 := VerifySignature(message, &public, r, s)
  fmt.Println(vrf1)

  // ASN.1 version
  signature := SignMessageASN1(message, key)
  vrf2 := VerifySignatureASN1(message, &public, signature)
  fmt.Println(vrf2)
}
