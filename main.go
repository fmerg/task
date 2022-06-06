package main

import (
  "fmt"
  "log"
  "math/big"
  "threshold/p256"
  "threshold/paillier"
)


func getPrimes256() (*big.Int, *big.Int) {

  // Fixed primes with bitlength>=256 for testing
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


func demoEcdsa() {
  key := p256.GenerateKey()
  public := key.Public()

  message := "to-be-signed"
  var verified bool

  // low level version
  r, s := key.Sign(message)
  verified = p256.VerifySignature(message, r, s, public)
  fmt.Println(verified)

  // ASN.1 version
  signature := key.SignASN1(message)
  verified = p256.VerifySignatureASN1(message, signature, public)
  fmt.Println(verified)
}

func demoPaillier() {
  bitLength := 8 * 256
  PBitLength := (bitLength + 1) / 2
  QBitLength := bitLength - PBitLength

  fmt.Println(PBitLength)
  fmt.Println(QBitLength)

  // P, _ := paillier.GenerateSafePrimes(PBitLength)
  // Q, _ := paillier.GenerateSafePrimes(QBitLength)
  P, Q := getPrimes256()

  secret := paillier.GenerateKey(P, Q)
  public := secret.Public()

  message := big.NewInt(9876543210)
  fmt.Println("message:", message)

  cipher := public.Encrypt(message)
  result := secret.Decrypt(cipher)

  fmt.Println("result:", result)
}


func demoPaillierFromCurve() {
  key := p256.GenerateKey()

  // TODO: Explain idea with reference to paper
  bitLength := 8 * p256.BitSize()
  PBitLength := (bitLength + 1) / 2
  QBitLength := bitLength - PBitLength

  // P, _ := paillier.GenerateSafePrimes(PBitLength)
  // Q, _ := paillier.GenerateSafePrimes(QBitLength)
  fmt.Println(QBitLength)
  fmt.Println(PBitLength)

  P, Q := getPrimes256()

  secret := paillier.GenerateKey(P, Q)
  public := secret.Public()

  message := key.Value()
  fmt.Println("message:", message)

  cipher := public.Encrypt(message)
  result := secret.Decrypt(cipher)

  fmt.Println("result:", result)
}


func demoPaillierWithProof() {
  key := p256.GenerateKey()

  // TODO: Explain idea with reference to paper
  bitLength := 8 * p256.BitSize()
  PBitLength := (bitLength + 1) / 2
  QBitLength := bitLength - PBitLength

  fmt.Println(QBitLength)
  fmt.Println(PBitLength)

  // P, _ := paillier.GenerateSafePrimes(PBitLength)
  // Q, _ := paillier.GenerateSafePrimes(QBitLength)
  P, Q := getPrimes256()

  secret := paillier.GenerateKey(P, Q)
  public := secret.Public()

  message := key.Value()
  fmt.Println("message:", message)

  y := key.Public()
  cipher, proof := public.EncryptWithProof(message, y)
  _, err := proof.Verify(y, cipher, public)
  if err != nil {
    log.Fatal(err)  // TODO: Handle
  }

  result := secret.Decrypt(cipher)
  fmt.Println("result:", result)
}


func main() {
  // demoEcdsa()
  demoPaillier()
  demoPaillierFromCurve()
  demoPaillierWithProof()
}
