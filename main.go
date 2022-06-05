package main

import (
  "core"
  "fmt"
  "math/big"
)


func demoEcdsa() {

  curve := core.Setup()
  key, public := core.KeyGen(curve)

  message := "to-be-signed"

  var verified bool

  // low level version
  r, s := core.Sign(message, key)
  verified = core.VerifySignature(message, &public, r, s)
  fmt.Println(verified)

  // ASN.1 version
  signature := core.SignASN1(message, key)
  verified = core.VerifySignatureASN1(message, &public, signature)
  fmt.Println(verified)
}

func demoPaillier() {

  bitLength := 8 * 256
  pBitLength := (bitLength + 1) / 2
  qBitLength := bitLength - pBitLength

  fmt.Println(pBitLength)
  fmt.Println(qBitLength)

  p, _ := new(big.Int).SetString(
    "17163161634662520191235013397610303324426988881329810102377024009423" +
    "35880140905321768768932843664364194840613742108650920446524799098111" +
    "51995088813137818874594756189243293450634966694077260781213716877906" +
    "08180451094068900726818512558568251625441150666217311612112006586486" +
    "7431825107133421624802764894257411059", 10)
  q, _ := new(big.Int).SetString(
    "15705873898913469909400178267257550228885122613981003807467211464383" +
    "33813079510250894803317554810377131913600144501867810386616519206592" +
    "00054569939347556380967956642459908629165456091047925197006764973541" +
    "29223536758794080599444958718778758463265731608001059144097229148919" +
    "0583394816326909520228507712914572539", 10)
  // p, _ := core.GenerateSafePrimes(pBitLength)
  // q, _ := core.GenerateSafePrimes(qBitLength)

  secret := core.NewPaillierKey(p, q)
  public := secret.Public()

  message := big.NewInt(9876543210)
  fmt.Println("message:", message)

  cipher := public.Encrypt(message)
  result := secret.Decrypt(cipher)

  fmt.Println("result:", result)
}


func demo() {
  curve := core.Setup()
  curve_bitsize := core.CryptoParams(curve).BitSize
  key, _ := core.KeyGen(curve)

  // TODO: Explain idea with reference to paper
  bitLength := 8 * curve_bitsize
  pBitLength := (bitLength + 1) / 2
  qBitLength := bitLength - pBitLength

  fmt.Println(qBitLength)
  fmt.Println(pBitLength)

  p, _ := new(big.Int).SetString(
    "17163161634662520191235013397610303324426988881329810102377024009423" +
    "35880140905321768768932843664364194840613742108650920446524799098111" +
    "51995088813137818874594756189243293450634966694077260781213716877906" +
    "08180451094068900726818512558568251625441150666217311612112006586486" +
    "7431825107133421624802764894257411059", 10)
  q, _ := new(big.Int).SetString(
    "15705873898913469909400178267257550228885122613981003807467211464383" +
    "33813079510250894803317554810377131913600144501867810386616519206592" +
    "00054569939347556380967956642459908629165456091047925197006764973541" +
    "29223536758794080599444958718778758463265731608001059144097229148919" +
    "0583394816326909520228507712914572539", 10)
  // p, _ := core.GenerateSafePrimes(pBitLength)
  // q, _ := core.GenerateSafePrimes(qBitLength)

  secret := core.NewPaillierKey(p, q)
  public := secret.Public()

  message := key.D
  fmt.Println("message:", message)

  cipher := public.Encrypt(message)
  result := secret.Decrypt(cipher)

  fmt.Println("result:", result)
}



func main() {

  // demoEcdsa()
  // demoPaillier()
  demo()
}
