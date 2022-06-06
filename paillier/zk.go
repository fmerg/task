package paillier

import (
  "math/big"
  // "crypto/rand"
  // "log"
  "fmt"
)


type ZKProof struct {
  setting *ZKSetting
  z       *big.Int
  u1      *big.Int
  u2      *big.Int
  u3      *big.Int
  e       *big.Int
  s1      *big.Int
  s2      *big.Int
  s3      *big.Int
}


type ZKSetting struct {
  NTilde  *big.Int        // N~
  h1      *big.Int        // h1
  h2      *big.Int        // h2
}


func generateZKSetting () *ZKSetting {
  NTilde := generateRSA(258).N
  h1 := randInt(NTilde)
  h2 := randInt(NTilde)

  return &ZKSetting {
    NTilde: NTilde,
    h1:     h1,
    h2:     h2,
  }
}


func (proof *ZKProof) Verify() (bool, error) {

  // Extract proof parameters (TODO: define and use helper)
  NTilde := proof.setting.NTilde
  h1 := proof.setting.h1
  h2 := proof.setting.h2
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

  err := fmt.Errorf("Proof failed to verify")
  return false, err
}
