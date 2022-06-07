package paillier

import (
    "math/big"
    "threshold/p256"
    "crypto/sha256"
    "fmt"
)


type ZKProof struct {
    ctx *ZKContext
    y   *p256.EcPublic
    z   *big.Int
    u1  *p256.EcPoint
    u2  *big.Int
    u3  *big.Int
    e   *big.Int
    s1  *big.Int
    s2  *big.Int
    s3  *big.Int
}


// ZK proof context under strong RSA assumption
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


// Generate ZK proof of knowledge that the provided cipher is the encyption of
// x under the provided Paillier public key. r should be the randomness used
// for encryption
func GenerateZKProof(x *p256.EcKey, cipher *big.Int, r *big.Int, public *PublicKey) *ZKProof {

    // Generate context under strong RSA assumption
    ctx := generateZKContext()
    NTilde := ctx.NTilde
    h1 := ctx.h1
    h2 := ctx.h2

    // Align with paper notation (Section 4.4, Pi_i)
    y := x.Public()
    eta := x.Value()
    w := cipher
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

    // z = h1 ^ eta * h2 ^ rho (mod N~)
    z := new(big.Int).Exp(h1, eta, NTilde)
    z.Mul(z, new(big.Int).Exp(h2, rho, NTilde)).Mod(z, NTilde)

    // u1 = a * g
    u1 := p256.Zero().BaseMult(alpha)

    // u2 = Gamma ^ a * beta * N (mod N ^ 2)
    u2 := new(big.Int).Exp(public.Gamma, alpha, public.NTo2)
    u2.Mul(u2, new(big.Int).Exp(beta, public.N, public.NTo2)).Mod(u2, public.NTo2)

    // u3 = h1 ^ a * h2 * gamma (mod N~)
    u3 := new(big.Int).Exp(h1, alpha, NTilde)
    u3.Mul(u3, new(big.Int).Exp(h2, gamma, NTilde)).Mod(u3, NTilde)

    // e = Hash(g, y, w, z, u1, u2, u3)
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
    e := new(big.Int).SetBytes(hasher.Sum(nil))

    // s1 = e * eta + alpha
    s1 := new(big.Int).Mul(e, eta)
    s1.Add(s1, alpha)

    // s2 = r ^ e * beta (mod N)
    s2 := new(big.Int).Exp(r, e, public.N)
    s2.Mul(s2, beta).Mod(s2, public.N)

    // s3 = e * rho + gamma
    s3 := new(big.Int).Mul(e, rho)
    s3.Add(s3, gamma)

    return &ZKProof{
        ctx:  ctx,
        y:    y,
        z:    z,
        u1:   u1,
        u2:   u2,
        u3:   u3,
        e:    e,
        s1:   s1,
        s2:   s2,
        s3:   s3,
    }
}


// Verify the present ZK-proof against provided cipher w and public Paillier
// key
func (proof *ZKProof) Verify(w *big.Int, public *PublicKey) (bool, error) {

    // Extract proof parameters
    NTilde := proof.ctx.NTilde
    h1 := proof.ctx.h1
    h2 := proof.ctx.h2
    y := proof.y
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

    // e == Hash(g, y, w, z, u1, u2, u3) ?
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
