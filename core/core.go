package core

import (
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/sha256"
  "crypto/rand"
  "hash"
  "fmt"
  "log"
  "io"
)


func Hash(message string) []byte {

  var h hash.Hash
  h = sha256.New()
  io.WriteString(h, message)

  return h.Sum(nil)
}


func KeyGen(curve elliptic.Curve) (*ecdsa.PrivateKey, ecdsa.PublicKey) {

  key, err := ecdsa.GenerateKey(curve, rand.Reader)

  if err != nil {
    log.Fatal(err)
  }

  return key, key.PublicKey
}


func DemoFlow() {

  // setup
  var curve elliptic.Curve
  curve = elliptic.P256()

  // var params *elliptic.CurveParams
  // params = curve.Params()

  // key generation
  key, public := KeyGen(curve)

  // message definition
  var message string
  message = "something"

  // sign/verify low level
  r, s, err := ecdsa.Sign(rand.Reader, key, Hash(message))
  if err != nil {
    log.Fatal(err)
  }
  sig := r.Bytes()
  sig = append(sig, s.Bytes()...)

  var vrf bool
  vrf = ecdsa.Verify(&public, Hash(message), r, s)

  // sign/verify ASN.1
  sig2, err := ecdsa.SignASN1(rand.Reader, key, Hash(message))
  if err != nil {
    log.Fatal(err)
  }

  var vrf2 bool
  vrf2 = ecdsa.VerifyASN1(&public, Hash(message), sig2)

  // Displays
  fmt.Println(vrf)
  fmt.Println(vrf2)
}
