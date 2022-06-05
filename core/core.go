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


func randomness(n *big.Int) *big.Int {
  r, err := rand.Int(rand.Reader, n)

  if err != nil {
    log.Fatal(err)
  }

  return r
}


type PaillierKey struct {
  p           *big.Int      // p
  q           *big.Int      // q
  N           *big.Int      // N, should be pq
  onePlusN    *big.Int      // 1 + N
  M           *big.Int      // N ^ 2
  totient     *big.Int      // phi(N)
  totientInv  *big.Int      // phi(N) ^ -1 (mod N)
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
  totientInv := new(big.Int).ModInverse(totient, N) // phi(N) ^ -1 (mod N)

  return &PaillierKey {
    p:          p,
    q:          q,
    N:          N,
    onePlusN:   onePlusN,
    M:          M,
    totient:    totient,
    totientInv: totientInv,
  }
}


func (key *PaillierKey) Public() *PaillierPub {
  return &PaillierPub {
    N:        key.N,
    onePlusN: key.onePlusN,
    M:        key.M,
  }
}


func Encrypt(public *PaillierPub, message *big.Int) *big.Int {

  onePlusNToM := new(big.Int).Exp(public.onePlusN, message, nil)  // (1 + N) ^ m
  rand := new(big.Int).Exp(randomness(public.N), public.N, nil)   // r ^ N
  aux := new(big.Int).Mul(onePlusNToM, rand)                      // (1 + N) ^ m * r ^ N
  cipher := new(big.Int).Mod(aux, public.M)                       // (1 + N) ^ m * r ^ N (mod N ^ 2)

  return cipher
}


func Decrypt(key *PaillierKey, cipher *big.Int) *big.Int {

  c_hat := new(big.Int).Exp(cipher, key.totient, key.M) // c^ = c ^ phi(N) (mod N ^ 2)
  tmp := new(big.Int).Sub(c_hat, big.NewInt(1))         // c^ - 1
  m_hat := new(big.Int).Div(tmp, key.N)                 // (c^ - 1)/N
  aux := new(big.Int).Mul(m_hat, key.totientInv)        // (c^ -1)/N * (phi(N) ^ -1 (mod N))
  decrypted := new(big.Int).Mod(aux, key.N)             // (c^ -1)/N * (phi(N) ^ -1 (mod N))  (mod N)

  return decrypted
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
