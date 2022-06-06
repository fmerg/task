package paillier

import (
  "math/big"
)


type ZKProof struct {
  z   *big.Int
  u1  *big.Int
  u2  *big.Int
  u3  *big.Int
  e   *big.Int
  s1  *big.Int
  s2  *big.Int
  s3  *big.Int
}


func (proof *ZKProof) Verify() (bool, error) {
  // TODO: Implement
  return true, nil
}
