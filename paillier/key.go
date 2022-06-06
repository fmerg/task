package paillier

import (
  // "crypto/elliptic"
  // "crypto/ecdsa"
  "threshold/p256"
  "math/big"
  "fmt"
)


type Key struct {
  P           *big.Int      // P
  Q           *big.Int      // Q
  N           *big.Int      // N, should be PQ
  NTo2        *big.Int      // N ^ 2
  Gamma       *big.Int      // 1 + N
  totient     *big.Int      // phi(N)
  totientInv  *big.Int      // phi(N) ^ -1 (mod N)
}


type PublicKey struct {
  N     *big.Int            // N
  NTo2  *big.Int            // N ^ 2
  Gamma *big.Int            // 1 + N
}


func GenerateKey(P *big.Int, Q *big.Int) *Key {

  one := big.NewInt(1)

  N := new(big.Int).Mul(P, Q)                         // N = PQ
  NTo2 := new(big.Int).Exp(N, big.NewInt(2), nil)     // N ^ 2
  Gamma := new(big.Int).Add(N, one)                   // 1 + N
  pMinusOne := new(big.Int).Sub(P, one)               // P - 1
  qMinusOne := new(big.Int).Sub(Q, one)               // Q - 1
  totient := new(big.Int).Mul(pMinusOne, qMinusOne)   // phi(N) = (P - 1)(Q - 1)
  totientInv := new(big.Int).ModInverse(totient, N)   // phi(N) ^ -1 (mod N)

  return &Key {
    P:          P,
    Q:          Q,
    N:          N,
    NTo2:       NTo2,
    Gamma:      Gamma,
    totient:    totient,
    totientInv: totientInv,
  }
}


func (key *Key) Public() *PublicKey {
  return &PublicKey {
    N:      key.N,
    NTo2:   key.NTo2,
    Gamma:  key.Gamma,
  }
}


func (public *PublicKey) Encrypt(message *big.Int) *big.Int {
  r := randInt(public.N)
  rToN := new(big.Int).Exp(r, public.N, public.NTo2) // r ^ N (mod N ^ 2)
  GammaToM := new(big.Int).Exp(public.Gamma, message, public.NTo2) // (1 + N) ^ m (mod N ^ 2)
  cipher := new(big.Int).Mul(GammaToM, rToN) // (1 + N) ^ m * r ^ N
  cipher = cipher.Mod(cipher, public.NTo2) // (1 + N) ^ m * r ^ N (mod N ^ 2)
  return cipher
}


func (public *PublicKey) EncryptWithProof(message *big.Int, y *p256.EcPublic) (*big.Int, *ZKProof) {
  // TODO: Implement
  r := randInt(public.N)
  rToN := new(big.Int).Exp(r, public.N, public.NTo2) // r ^ N (mod N ^ 2)
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
  q := p256.Order()
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

  // u1 = a * g E G
  u1 := p256.ScalarTimesGen(alpha)

  // u2 = Gamma ^ a * beta * N (mod N ^ 2)
  u2 := new(big.Int).Exp(public.Gamma, alpha, public.NTo2)
  u2.Mul(u2, new(big.Int).Exp(beta, public.N, public.NTo2)).Mod(u2, public.NTo2)

  // u3 = h1 ^ a * h2 * gamma (mod N~)
  u3 := new(big.Int).Exp(h1, alpha, NTilde)
  u3.Mul(u3, new(big.Int).Exp(h2, gamma, NTilde)).Mod(u3, NTilde)

  // TODO: Initialize appropriately
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

  c_hat := new(big.Int).Exp(cipher, key.totient, key.NTo2) // c^ = c ^ phi(N) (mod N ^ 2)
  tmp := new(big.Int).Sub(c_hat, big.NewInt(1)) // c^ - 1
  m_hat := new(big.Int).Div(tmp, key.N) // (c^ - 1) / N

  result := new(big.Int).Mul(m_hat, key.totientInv) // ((c^ -1) / N) * (phi(N) ^ -1 (mod N))
  result = result.Mod(result, key.N)  // ((c^ -1) / N) * (phi(N) ^ -1 (mod N))  (mod N)
  return result
}
