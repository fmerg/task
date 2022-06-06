package paillier


import (
  "crypto/rand"
  "math/big"
  "log"
  "fmt"
)


func randInt(max *big.Int) *big.Int {
  r, err := rand.Int(rand.Reader, max)

  if err != nil {
    log.Fatal(err)
  }

  return r
}


func randInRange(min *big.Int, max *big.Int) *big.Int {
	if min.Cmp(max) >= 0 {
    log.Fatal("max is < min")
	}

  r, err := rand.Int(rand.Reader, new(big.Int).Sub(max, min))

  if err != nil {
    log.Fatal(err)
  }

	r.Add(r, min)
	return r
}


// Generate prime numbers p, q = (p - 1)/2 with bitlength(p) >= bitLen
func GenerateSafePrimes(bitLength int) (*big.Int, *big.Int) {
  p := new(big.Int)

  count := 0
  for {
    fmt.Println(count)
    count ++
    q, err := rand.Prime(rand.Reader, bitLength - 1)

    if err != nil {
      log.Fatal(err)
    }

    // p = 2 * q + 1 = (q << 1) ^ 1
    p.Lsh(q, 1)
    p.SetBit(p, 0, 1)

    // Miller-Rabin primality test for p failing with probability at most equal
    // to (1/4) ^ 25
    if p.ProbablyPrime(25) {
      return p, q
    }
  }
}
