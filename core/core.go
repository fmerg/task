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

func DemoFlow() {

  // setup
  var curve elliptic.Curve
  curve = elliptic.P256()

  // var params *elliptic.CurveParams
  // params = curve.Params()

  // key generation
  privKey := new(ecdsa.PrivateKey)
  privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
  if err != nil {
    log.Fatal(err)
  }

  // public extraction
  var pubKey ecdsa.PublicKey
  pubKey = privKey.PublicKey

  // message definition
  var message string
  message = "something"

  // message commitment
  var h hash.Hash
  var digest []byte
  h = sha256.New()
  io.WriteString(h, message)
  digest = h.Sum(nil)

  // sign/verify low level
  r, s, err := ecdsa.Sign(rand.Reader, privKey, digest)
  if err != nil {
    log.Fatal(err)
  }
  sig := r.Bytes()
  sig = append(sig, s.Bytes()...)

  var vrf bool
  vrf = ecdsa.Verify(&pubKey, digest, r, s)

  // sign/verify ASN.1
  sig2, err := ecdsa.SignASN1(rand.Reader, privKey, digest)
  if err != nil {
    log.Fatal(err)
  }

  var vrf2 bool
  vrf2 = ecdsa.VerifyASN1(&pubKey, digest, sig2)

  // Displays
  fmt.Println(sig)
  fmt.Println(vrf)
  fmt.Println(sig2)
  fmt.Println(vrf2)
}
