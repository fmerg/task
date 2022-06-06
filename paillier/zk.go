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


func (proof *ZKProof) extractSetting() (*big.Int, *big.Int, *big.Int) {
  setting := proof.setting

  NTilde := setting.NTilde
  h1 := setting.h1
  h2 := setting.h2

  return NTilde, h1, h2
}


func (proof *ZKProof) Verify() (bool, error) {
  // TODO: Implement

  // NTilde, h1, h2 := proof.extractSetting()
  // fmt.Println(NTilde)
  // fmt.Println(h1)
  // fmt.Println(h2)

  err := fmt.Errorf("Proof failed to verify")
  return false, err
}
