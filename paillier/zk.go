package paillier

import (
  "math/big"
  "threshold/p256"
  "crypto/sha256"
  "fmt"
)


type ZKProof struct {
  ctx *ZKContext
  z   *big.Int
  u1  *p256.EcPoint
  u2  *big.Int
  u3  *big.Int
  e   *big.Int
  s1  *big.Int
  s2  *big.Int
  s3  *big.Int
}


type ZKContext struct {
  NTilde  *big.Int
  h1      *big.Int
  h2      *big.Int
}


func generateZKContext () *ZKContext {
  NTilde := generateRSA(258).N
  h1 := randInt(NTilde)
  h2 := randInt(NTilde)

  return &ZKContext {
    NTilde: NTilde,
    h1:     h1,
    h2:     h2,
  }
}


func (proof *ZKProof) Verify(y *p256.EcPublic, w *big.Int, public *PublicKey) (bool, error) {

  // Extract proof parameters (TODO: define and use helper)
  NTilde := proof.ctx.NTilde
  h1 := proof.ctx.h1
  h2 := proof.ctx.h2
  z := proof.z
  u1 := proof.u1
  u2 := proof.u2
  u3 := proof.u3
  e := proof.e
  s1 := proof.s1
  s2 := proof.s2
  s3 := proof.s3

  // s1 * g == u1 + e * y ?
  lu1 := p256.Zero().BaseMult(s1)
  ru1 := p256.Zero().Add(u1, p256.Zero().Mult(e, y.ToPoint()))
  u1check := lu1.IsEqual(ru1)

  // Gamma ^ s1 * s2 ^ N == u2 * w ^ e (mod N ^ 2) ?
  lu2 := new(big.Int).Exp(public.Gamma, s1, public.NTo2)
  lu2.Mul(lu2, new(big.Int).Exp(s2, public.N, public.NTo2)).Mod(lu2, public.NTo2)
  ru2 := new(big.Int).Mul(u2, new(big.Int).Exp(w, e, public.NTo2))
  ru2.Mod(ru2, public.NTo2)
  u2check := lu2.Cmp(ru2) == 0

  // h1 ^ s1 * h2 ^ s3 == u3 * z ^ e (mod N~) ?
  lu3 := new(big.Int).Exp(h1, s1, NTilde)
  lu3.Mul(lu3, new(big.Int).Exp(h2, s3, NTilde)).Mod(lu3, NTilde)
  ru3 := new(big.Int).Mul(u3, new(big.Int).Exp(z, e, NTilde))
  ru3.Mod(ru3, NTilde)
  u3check := lu3.Cmp(ru3) == 0

  // e = Hash(g, y, w, z, u1, u2, u3) E Z
  hasher := sha256.New()
  gx, gy := p256.Generator().ToBytes()
  hasher.Write(gx)
  hasher.Write(gy)
  yx, yy := y.ToBytes()
  hasher.Write(yx)
  hasher.Write(yy)
  hasher.Write(w.Bytes())
  hasher.Write(z.Bytes())
  u1x, u1y := u1.ToBytes()
  hasher.Write(u1x)
  hasher.Write(u1y)
  hasher.Write(u2.Bytes())
  hasher.Write(u3.Bytes())
  d := new(big.Int).SetBytes(hasher.Sum(nil))
  echeck := e.Cmp(d) == 0

  if (u1check && u2check && u3check && echeck) {
    return true, nil
  }

  err := fmt.Errorf("Proof failed to verify")
  return false, err
}
