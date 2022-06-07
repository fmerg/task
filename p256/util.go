package p256

import (
  "crypto/sha256"
  "hash"
  "io"
)


func hashText(message string) []byte {
  var hasher hash.Hash
  hasher = sha256.New()
  io.WriteString(hasher, message)

  return hasher.Sum(nil)
}
