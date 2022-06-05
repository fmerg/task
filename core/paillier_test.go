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

  secret := core.NewPaillierKey(p, q)
  public := secret.Public()

  m := big.NewInt(175)
  c := core.Encrypt(public, m)
  d := core.Decrypt(secret, c)

  assert.Equal(t, m, d, "Decrypted ciphertext is not original message")
}
