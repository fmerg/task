package paillier

import (
  "threshold/p256"
  "math/big"
)


// Paillier key (N, phi(N)) with precomputed quantities for calculations
type Key struct {
    N           *big.Int  // N
    NTo2        *big.Int  // N ^ 2
    Gamma       *big.Int  // 1 + N
    totient     *big.Int  // phi(N)
    totientInv  *big.Int  // phi(N) ^ -1 (mod N)
}


// Public part of Paillier key
type PublicKey struct {
    N     *big.Int
    NTo2  *big.Int
    Gamma *big.Int
}


// Paillier key generation with N = PQ
func GenerateKey(P *big.Int, Q *big.Int) *Key {
    one := big.NewInt(1)

    N := new(big.Int).Mul(P, Q) // N = PQ
    NTo2 := new(big.Int).Exp(N, big.NewInt(2), nil) // N ^ 2
    Gamma := new(big.Int).Add(N, one) // 1 + N
    pMinusOne := new(big.Int).Sub(P, one) // P - 1
    qMinusOne := new(big.Int).Sub(Q, one) // Q - 1
    totient := new(big.Int).Mul(pMinusOne, qMinusOne) // phi(N) = (P - 1)(Q - 1)
    totientInv := new(big.Int).ModInverse(totient, N) // phi(N) ^ -1 (mod N)

    return &Key {
        N:          N,
        NTo2:       NTo2,
        Gamma:      Gamma,
        totient:    totient,
        totientInv: totientInv,
    }
}


// Returns the public part of the present Paillier key
func (key *Key) Public() *PublicKey {
    return &PublicKey {
        N:      key.N,
        NTo2:   key.NTo2,
        Gamma:  key.Gamma,
    }
}


// Encrypts the provided message while also returning the randomness used for
// encryption. This is intended for internal usage only.
func (public *PublicKey) encryptWithRand(message *big.Int) (*big.Int, *big.Int) {

    r := randInt(public.N)

    // r ^ N (mod N ^ 2)
    rToN := new(big.Int).Exp(r, public.N, public.NTo2)

    // (1 + N) ^ m (mod N ^ 2)
    GammaToM := new(big.Int).Exp(public.Gamma, message, public.NTo2)

    // (1 + N) ^ m * r ^ N (mod N ^ 2)
    cipher := new(big.Int).Mul(GammaToM, rToN)
    cipher = cipher.Mod(cipher, public.NTo2)

    return cipher, r
}


// Standard encryption with respect to the present Paillier public key
func (public *PublicKey) Encrypt(message *big.Int) *big.Int {

    cipher, _ := public.encryptWithRand(message)

    return cipher
}


// Standard decryption with respect to the present Paillier key
func (key *Key) Decrypt(cipher *big.Int) *big.Int {

    // m^ = (c ^ phi(N) (mod N ^ 2) - 1) / N
    m_hat := new(big.Int).Exp(cipher, key.totient, key.NTo2)
    m_hat = m_hat.Sub(m_hat, big.NewInt(1))
    m_hat = m_hat.Div(m_hat, key.N)

    // m^ * (phi(N) ^ -1 (mod N)) (mod N)
    res := new(big.Int).Mul(m_hat, key.totientInv)
    res = res.Mod(res, key.N)

    return res
}


// Encrypt the value of the provided elliptic key and return ZP proof along
// with cipher
func (public *PublicKey) EncryptEcKey(x *p256.EcKey) (*big.Int, *ZKProof) {

    cipher, r := public.encryptWithRand(x.Value())
    proof := GenerateZKProof(x, cipher, r, public)

    return cipher, proof
}
