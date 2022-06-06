package paillier

import (
  "math/big"
  "fmt"
)


type Key struct {
  p           *big.Int      // p
  q           *big.Int      // q
  N           *big.Int      // N, should be pq
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


func GenerateKey(p *big.Int, q *big.Int) *Key {

  one := big.NewInt(1)

  N := new(big.Int).Mul(p, q)                         // N = pq
  M := new(big.Int).Exp(N, big.NewInt(2), nil)        // N ^ 2
  Gamma := new(big.Int).Add(N, one)                   // 1 + N
  pMinusOne := new(big.Int).Sub(p, one)               // p - 1
  qMinusOne := new(big.Int).Sub(q, one)               // q - 1
  totient := new(big.Int).Mul(pMinusOne, qMinusOne)   // phi(N) = (p - 1)(q - 1)
  totientInv := new(big.Int).ModInverse(totient, N)   // phi(N) ^ -1 (mod N)

  return &Key {
    p:          p,
    q:          q,
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


func (public *PublicKey) EncryptWithProof(message *big.Int) (*big.Int, *ZKProof) {
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

  fmt.Println(h1)
  fmt.Println(h2)

  // Generate random parameters

  q := big.NewInt(7)  // TODO: pass this somehow
  qNTilde := new(big.Int).Mul(q, NTilde) // q * N~
  qTo3 := new(big.Int).Exp(q, big.NewInt(3), nil) // q ^ 3
  qTo3NTilde := new(big.Int).Mul(qTo3, NTilde) // q ^ 3 * N~

  one := big.NewInt(1)

  alpha := randInRange(one, qTo3)
  beta := randInRange(one, public.N)
  rho := randInRange(one, qNTilde)
  gamma := randInRange(one, qTo3NTilde)

  fmt.Println(alpha)
  fmt.Println(beta)
  fmt.Println(rho)
  fmt.Println(gamma)

  // TODO: Initialize appropriately
  z := big.NewInt(0)
  u1 := big.NewInt(0)
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
