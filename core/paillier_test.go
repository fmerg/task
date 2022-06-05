package core_test

import (
  "core"
  "testing"
  "github.com/stretchr/testify/assert"
  "math/big"
)


func TestEncryptDecrypt(t *testing.T) {

  p := big.NewInt(11)
  q := big.NewInt(17)
  N := new(big.Int).Mul(p, q)

  m := big.NewInt(175)
  c := core.Encrypt(N, m)
  d := core.Decrypt(p, q, c)

  assert.Equal(t, m, d, "Decrypted ciphertext is not original message")
}
