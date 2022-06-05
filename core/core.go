package core

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


func EulerPhi(p *big.Int, q *big.Int) *big.Int {
  one := big.NewInt(1)
  pMinusOne := new(big.Int).Sub(p, one)
  qMinusOne := new(big.Int).Sub(q, one)
  return new(big.Int).Mul(pMinusOne, qMinusOne)
}


func randomness(n *big.Int) *big.Int {
  r, err := rand.Int(rand.Reader, n)

  if err != nil {
    log.Fatal(err)
  }

  return r
}


type PaillierKey struct {
  p         *big.Int      // p
  q         *big.Int      // q
  N         *big.Int      // N
  onePlusN  *big.Int      // 1 + N
  M         *big.Int      // N ^ 2
  totient   *big.Int      // phi(N)
}


type PaillierPub struct {
  N         *big.Int      // N
  onePlusN  *big.Int      // 1 + N
  M         *big.Int      // N * 2
}


func NewPaillierKey(p *big.Int, q *big.Int) *PaillierKey {

  one := big.NewInt(1)
  two := big.NewInt(2)

  pMinusOne := new(big.Int).Sub(p, one)             // p - 1
  qMinusOne := new(big.Int).Sub(q, one)             // q - 1

  N := new(big.Int).Mul(p, q)                       // N = pq
  onePlusN := new(big.Int).Add(N, one)              // 1 + N
  M := new(big.Int).Exp(N, two, nil)                // N ^ 2
  totient := new(big.Int).Mul(pMinusOne, qMinusOne) // phi(N) = (p - 1)(q - 1)

  return &PaillierKey {
    p:        p,
    q:        q,
    N:        N,
    onePlusN: onePlusN,
    M:        M,
    totient:  totient,
  }
}


func (key *PaillierKey) Public() *PaillierPub {
  return &PaillierPub {
    N:        key.N,
    onePlusN: key.onePlusN,
    M:        key.M,
  }
}


func Encrypt(N *big.Int, m *big.Int) *big.Int {

  one := big.NewInt(1)
  two := big.NewInt(2)

  onePlusN := new(big.Int).Add(N, one)              // 1 + N
  M := new(big.Int).Exp(N, two, nil)                // N ^ 2

  onePlusNToM := new(big.Int).Exp(onePlusN, m, nil) // (1 + N) ^ m

  r := randomness(N)
  rToN := new(big.Int).Exp(r, N, nil)         // r ^ N

  aux := new(big.Int).Mul(onePlusNToM, rToN)  // (1 + N) ^ m * r ^ N
  c := new(big.Int).Mod(aux, M)               // (1 + N) ^ m * r ^ N (mod N ^ 2)
  return c
}


func Decrypt(p *big.Int, q *big.Int, c *big.Int) *big.Int {

  one := big.NewInt(1)
  two := big.NewInt(2)

  N := new(big.Int).Mul(p, q)                   // N
  M := new(big.Int).Exp(N, two, nil)            // N ^ 2

  totient := EulerPhi(p, q)                     // phi(N)

  c_hat := new(big.Int).Exp(c, totient, M)      // c ^ phi(N) (mod N ^ 2)

  tmp := new(big.Int).Sub(c_hat, one)
  m_hat := new(big.Int).Div(tmp, N)     // (c ^ phi(N) (mod N ^ 2) - 1)/N

  totientInverse := new(big.Int).ModInverse(totient, N) // phi(N) ^ -1 (mod N ^ 2)

  tmp2 := new(big.Int).Mul(m_hat, totientInverse)
  d := new(big.Int).Mod(tmp2, N)

  return d
}


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
