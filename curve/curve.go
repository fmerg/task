package curve

import (
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/sha256"
  "crypto/rand"
  "math/big"
  "hash"
  "log"
  "io"
)

func Setup() elliptic.Curve {

  return elliptic.P256()
}


func CryptoParams(curve elliptic.Curve) *elliptic.CurveParams {

  return curve.Params()
}


func HashText(message string) []byte {

  var hasher hash.Hash
  hasher = sha256.New()
  io.WriteString(hasher, message)

  return hasher.Sum(nil)
}


func KeyGen(curve elliptic.Curve) (*ecdsa.PrivateKey, ecdsa.PublicKey) {

  key, err := ecdsa.GenerateKey(curve, rand.Reader)

  if err != nil {
    log.Fatal(err)
  }

  return key, key.PublicKey
}


func Sign(message string, key *ecdsa.PrivateKey) (*big.Int, *big.Int) {

  r, s, err := ecdsa.Sign(rand.Reader, key, HashText(message))

  if err != nil {
    log.Fatal(err)
  }

  return r, s
}


func VerifySignature(message string, public *ecdsa.PublicKey, r, s *big.Int) bool {

  return ecdsa.Verify(public, HashText(message), r, s)
}


func SignASN1(message string, key *ecdsa.PrivateKey) []byte {

  signature, err := ecdsa.SignASN1(rand.Reader, key, HashText(message))

  if err != nil {
    log.Fatal(err)
  }

  return signature
}


func VerifySignatureASN1(message string, public *ecdsa.PublicKey, signature []byte) bool {

  return ecdsa.VerifyASN1(public, HashText(message), signature)
}
