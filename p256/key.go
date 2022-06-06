package p256

import (
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/rand"
  "math/big"
  "log"
)


type EcKey struct {
  priv  *ecdsa.PrivateKey
  pub   *ecdsa.PublicKey
}


type EcPublic struct {
  _wrapped *ecdsa.PublicKey
}


func (pub *EcPublic) ToBytes() ([]byte, []byte) {
  x := pub._wrapped.X
  y := pub._wrapped.Y

  return x.Bytes(), y.Bytes()
}


func GenerateKey() *EcKey {
  curve := elliptic.P256()
  priv, err := ecdsa.GenerateKey(curve, rand.Reader)

  if err != nil {
    log.Fatal(err)
  }

  pub := &priv.PublicKey

  return &EcKey {
    priv: priv,
    pub:  pub,
  }
}


func (key *EcKey) Value() *big.Int {

  return key.priv.D
}


func (key *EcKey) Public() *EcPublic {

  return &EcPublic {
    _wrapped: key.pub,
  }
}


func (key *EcKey) Sign(message string) (*big.Int, *big.Int) {

  r, s, err := ecdsa.Sign(rand.Reader, key.priv, hashText(message))

  if err != nil {
    log.Fatal(err)
  }

  return r, s
}


func (key *EcKey) SignASN1(message string) []byte {

  signature, err := ecdsa.SignASN1(rand.Reader, key.priv, hashText(message))

  if err != nil {
    log.Fatal(err)
  }

  return signature
}


func VerifySignature(message string, r *big.Int, s *big.Int, public *EcPublic) bool {

  return ecdsa.Verify(public._wrapped, hashText(message), r, s)
}


func VerifySignatureASN1(message string, signature []byte, public *EcPublic) bool {

  return ecdsa.VerifyASN1(public._wrapped, hashText(message), signature)
}
