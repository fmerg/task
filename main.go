package main

import (
  "fmt"
  "log"
  "math/big"
  "threshold/p256"
  "threshold/paillier"
)


// Fixed primes with bitlength>=256 for testing
func getPrimes256() (*big.Int, *big.Int) {
  P, _ := new(big.Int).SetString(
    "17163161634662520191235013397610303324426988881329810102377024009423" +
    "35880140905321768768932843664364194840613742108650920446524799098111" +
    "51995088813137818874594756189243293450634966694077260781213716877906" +
    "08180451094068900726818512558568251625441150666217311612112006586486" +
    "7431825107133421624802764894257411059", 10)
  Q, _ := new(big.Int).SetString(
    "15705873898913469909400178267257550228885122613981003807467211464383" +
    "33813079510250894803317554810377131913600144501867810386616519206592" +
    "00054569939347556380967956642459908629165456091047925197006764973541" +
    "29223536758794080599444958718778758463265731608001059144097229148919" +
    "0583394816326909520228507712914572539", 10)

  return P, Q
}


func demoEncDec() {
  x := p256.GenerateKey()

  // // TODO: Explain idea with reference to paper
  // bitLength := 8 * p256.BitSize()
  // PBitLength := (bitLength + 1) / 2
  // QBitLength := bitLength - PBitLength
  // // P, _ := paillier.GenerateSafePrimes(PBitLength)
  // // Q, _ := paillier.GenerateSafePrimes(QBitLength)

  P, Q := getPrimes256()
  key := paillier.GenerateKey(P, Q)
  public := key.Public()

  message := x.Value()
  fmt.Println("message:", message)
  cipher := public.Encrypt(message)
  result := key.Decrypt(cipher)
  fmt.Println("result:", result)
}


func demoEncDecWithProof() {
  x := p256.GenerateKey()
  y := x.Public()

  // // TODO: Explain idea with reference to paper
  // bitLength := 8 * p256.BitSize()
  // PBitLength := (bitLength + 1) / 2
  // QBitLength := bitLength - PBitLength
  // // P, _ := paillier.GenerateSafePrimes(PBitLength)
  // // Q, _ := paillier.GenerateSafePrimes(QBitLength)

  P, Q := getPrimes256()
  key := paillier.GenerateKey(P, Q)
  public := key.Public()

  message := x.Value()
  fmt.Println("message:", message)
  cipher, proof := public.EncryptWithProof(message, y)
  _, err := proof.Verify(y, cipher, public)
  if err != nil {
    log.Fatal(err)
  }
  result := key.Decrypt(cipher)
  fmt.Println("result:", result)
}


func main() {
  demoEncDec()
  demoEncDecWithProof()
}
