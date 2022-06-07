package p256

import (
    "testing"
    "github.com/stretchr/testify/assert"
)


func TestSignVerify(t *testing.T) {
    key := GenerateKey()
    public := key.Public()
    message := "to-be-signed"
    r, s := key.Sign(message)
    status := VerifySignature(message, r, s, public)
    assert.True(t, status, "Siganture should verify")
}


func TestSignVerifyASN1(t *testing.T) {
    key := GenerateKey()
    public := key.Public()
    message := "to-be-signed"
    signature := key.SignASN1(message)
    status := VerifySignatureASN1(message, signature, public)
    assert.True(t, status, true, "Siganture should verify")
}
