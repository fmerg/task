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

  message := big.NewInt(175)

  cipher := public.Encrypt(message)
  result := secret.Decrypt(cipher)

  assert.Equal(t, message, result, "Decrypted ciphertext is not original message")
}
