package paillier


import (
  "crypto/rand"
  "crypto/rsa"
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


// Generate odd prime numbers P, Q = (P - 1)/2 with bitlength(P) >= bitLen
// TODO: Optimize
func GenerateSafePrimes(bitLength int) (*big.Int, *big.Int) {
  P := new(big.Int)

  count := 0
  for {
    fmt.Println(count)
    count ++
    Q, err := rand.Prime(rand.Reader, bitLength - 1)

    if err != nil {
      log.Fatal(err)
    }

    // P = 2 * Q + 1 = (Q << 1) ^ 1
    P.Lsh(Q, 1)
    P.SetBit(P, 0, 1)

    // Miller-Rabin primality test for P failing with probability at most equal
    // to (1/4) ^ 25
    if P.ProbablyPrime(25) {
      return P, Q
    }
  }
}

// TODO: Explain what we need this for
func generateRSA(bitlength int) *rsa.PrivateKey {
  key, err := rsa.GenerateKey(rand.Reader, 2048)

  if err != nil {
    log.Fatal(err)
  }

  return key
}
