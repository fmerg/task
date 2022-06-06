package paillier

import (
  "crypto/elliptic"
  // "crypto/ecdsa"
  "threshold/p256"
  "math/big"
  "fmt"
)


type Key struct {
  P           *big.Int      // P
  Q           *big.Int      // Q
  N           *big.Int      // N, should be PQ
  M           *big.Int      // N ^ 2
  Gamma       *big.Int      // 1 + N
  totient     *big.Int      // phi(N)
  totientInv  *big.Int      // phi(N) ^ -1 (mod N)
}


type PublicKey struct {
  N     *big.Int            // N
  M     *big.Int            // N ^ 2
  Gamma *big.Int            // 1 + N
}


func GenerateKey(P *big.Int, Q *big.Int) *Key {

  one := big.NewInt(1)

  N := new(big.Int).Mul(P, Q)                         // N = PQ
  M := new(big.Int).Exp(N, big.NewInt(2), nil)        // N ^ 2
  Gamma := new(big.Int).Add(N, one)                   // 1 + N
  pMinusOne := new(big.Int).Sub(P, one)               // P - 1
  qMinusOne := new(big.Int).Sub(Q, one)               // Q - 1
  totient := new(big.Int).Mul(pMinusOne, qMinusOne)   // phi(N) = (P - 1)(Q - 1)
  totientInv := new(big.Int).ModInverse(totient, N)   // phi(N) ^ -1 (mod N)

  return &Key {
    P:          P,
    Q:          Q,
    N:          N,
    M:          M,
    Gamma:      Gamma,
    totient:    totient,
    totientInv: totientInv,
  }
}


func (key *Key) Public() *PublicKey {
  return &PublicKey {
    N:      key.N,
    M:      key.M,
    Gamma:  key.Gamma,
  }
}


func (public *PublicKey) Encrypt(message *big.Int) *big.Int {
  r := randInt(public.N)
  rToN := new(big.Int).Exp(r, public.N, public.M) // r ^ N (mod N ^ 2)
  GammaToM := new(big.Int).Exp(public.Gamma, message, public.M) // (1 + N) ^ m (mod N ^ 2)
  cipher := new(big.Int).Mul(GammaToM, rToN) // (1 + N) ^ m * r ^ N
  cipher = cipher.Mod(cipher, public.M) // (1 + N) ^ m * r ^ N (mod N ^ 2)
  return cipher
}


func (public *PublicKey) EncryptWithProof(message *big.Int, _curve elliptic.Curve, y *p256.EcPublic) (*big.Int, *ZKProof) {
  // TODO: Implement
  r := randInt(public.N)
  rToN := new(big.Int).Exp(r, public.N, public.M) // r ^ N (mod N ^ 2)
  fmt.Println(rToN)

  cipher := big.NewInt(0)

  // Generate proof setting
  setting := generateZKSetting()

  NTilde := setting.NTilde
  h1 := setting.h1
  h2 := setting.h2

  // Adapt encryption parameters
  eta := message  // secret key to encrypt

  // Adapt proof setting with respect to q
  q := _curve.Params().P
  qNTilde := new(big.Int).Mul(q, NTilde) // q * N~
  qTo3 := new(big.Int).Exp(q, big.NewInt(3), nil) // q ^ 3
  qTo3NTilde := new(big.Int).Mul(qTo3, NTilde) // q ^ 3 * N~

  // Generate random parameters
  one := big.NewInt(1)
  alpha := randInRange(one, qTo3)
  beta := randInRange(one, public.N)  // TODO: Justify
  rho := randInRange(one, qNTilde)
  gamma := randInRange(one, qTo3NTilde)

  fmt.Println(alpha, beta, gamma)

  // z = h1 ^ eta * h2 ^ rho (mod N~)
  z := new(big.Int).Exp(h1, eta, NTilde)
  z.Mul(z, new(big.Int).Exp(h2, rho, NTilde)).Mod(z, NTilde)

  // u1 = g ^ a E G
  u1 := big.NewInt(0)

  // TODO: Initialize appropriately
  u2 := big.NewInt(0)
  u3 := big.NewInt(0)
  e := big.NewInt(0)
  s1 := big.NewInt(0)
  s2 := big.NewInt(0)
  s3 := big.NewInt(0)

  proof := &ZKProof{
    setting:  setting,
    z:        z,
    u1:       u1,
    u2:       u2,
    u3:       u3,
    e:        e,
    s1:       s1,
    s2:       s2,
    s3:       s3,
  }

  return cipher, proof
}


func (key *Key) Decrypt(cipher *big.Int) *big.Int {

  c_hat := new(big.Int).Exp(cipher, key.totient, key.M) // c^ = c ^ phi(N) (mod N ^ 2)
  tmp := new(big.Int).Sub(c_hat, big.NewInt(1)) // c^ - 1
  m_hat := new(big.Int).Div(tmp, key.N) // (c^ - 1) / N

  result := new(big.Int).Mul(m_hat, key.totientInv) // ((c^ -1) / N) * (phi(N) ^ -1 (mod N))
  result = result.Mod(result, key.N)  // ((c^ -1) / N) * (phi(N) ^ -1 (mod N))  (mod N)
  return result
}
