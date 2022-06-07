package paillier

import (
  "testing"
  "github.com/stretchr/testify/assert"
  "math/big"
  "threshold/p256"
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


func TestEncryptDecrypt(t *testing.T) {
  // P, _ := paillier.GenerateSafePrimes(PBitLength)
  // Q, _ := paillier.GenerateSafePrimes(QBitLength)
  P, Q := getPrimes256()
  key := GenerateKey(P, Q)
  public := key.Public()
  message := big.NewInt(9876543210)
  cipher := public.Encrypt(message)
  result := key.Decrypt(cipher)
  assert.Equal(t, message, result, "Decrypted ciphertext is not original message")
}


func TestEncryptDecryptEcKey(t *testing.T) {
  x := p256.GenerateKey()
  y := x.Public()
  // P, _ := paillier.GenerateSafePrimes(PBitLength)
  // Q, _ := paillier.GenerateSafePrimes(QBitLength)
  P, Q := getPrimes256()
  key := GenerateKey(P, Q)
  public := key.Public()
  cipher, proof := public.EncryptEcKey(x)
  result, err := key.DecryptEcKey(y, cipher, proof)
  assert.Equal(t, err, nil, "Proof should have verified")
  assert.Equal(t, result, x.Value(), "Decrpted ciphertext is not the awaited key")
}
