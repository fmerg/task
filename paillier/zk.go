package paillier

import (
  "math/big"
  "threshold/p256"
  "crypto/sha256"
  // "log"
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

  fmt.Println(NTilde, h1, h2, z, u1, u2, u3, e, s1, s2, s3)

  // TODO: Do checks

  // s1 * g - e * y   TODO
  _u1 := p256.ScalarTimesGen(s1).Add(y.ToPoint().Neg().ScalarMult(e))
  fmt.Println(_u1)
  fmt.Println(u1)

  // -----------------------
  // u2 = Gamma ^ s1 * s2 ^ N * w ^ -e (mod N ^ 2)
  _u2 := new(big.Int).Exp(public.Gamma, s1, public.NTo2)
  _u2.Mul(_u2, new(big.Int).Exp(s2, public.N, public.NTo2).Mod(_u2, public.NTo2))
  _u2.Mul(_u2, new(big.Int).ModInverse(new(big.Int).Exp(w, e, public.NTo2), public.NTo2)).Mod(_u2, public.NTo2)
  fmt.Println(_u2)
  fmt.Println(u2)
  // -----------------------

  // // -----------------------
  // // u3 = h1 ^ s1 * h2 ^ s3 * z ^ -e (mod N ^ 2)
  // _u3 := new(big.Int).Exp(h1, s1, public.NTo2)
  // _u3 = _u3.Mul(_u3, new(big.Int).Exp(h2, s3, public.NTo2)).Mod(_u3, public.NTo2)
  // _u3.Mul(_u3, new(big.Int).Exp(w, new(big.Int).ModInverse(e, public.NTo2), public.NTo2)).Mod(_u3, public.NTo2)
  // fmt.Println(_u3)
  // fmt.Println(u3)
  // // -----------------------

  // // ------------------------
  // // e = Hash(g, y, w, z, u1, u2, u3) E Z
  hasher := sha256.New()
  hasher.Reset()
  // gx, gy := p256.Generator().ToBytes()
  // hasher.Write(gx)
  // hasher.Write(gy)
  // yx, yy := y.ToBytes()
  // hasher.Write(yx)
  // hasher.Write(yy)
  // hasher.Write(w.Bytes())
  // hasher.Write(z.Bytes())
  // u1x, u1y := u1.ToBytes()
  // hasher.Write(u1x)
  // hasher.Write(u1y)
  // hasher.Write(u2.Bytes())
  // hasher.Write(u3.Bytes())
  // _e := new(big.Int).SetBytes(hasher.Sum(nil))
  // fmt.Println(_e)
  // fmt.Println(e)
  // // ------------------------

  err := fmt.Errorf("Proof failed to verify")
  return false, err
}
