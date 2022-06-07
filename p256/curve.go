package p256

import (
  "crypto/elliptic"
  "math/big"
)


// Order of underlying field
func Order() *big.Int {

  return elliptic.P256().Params().P
}


// Bit size of underlying field
func BitSize() int {

  return elliptic.P256().Params().BitSize
}


// Representation of curve points as (x, y) tuples
type EcPoint struct {
  x *big.Int
  y *big.Int
}


// Returns the zero point of the curve
func Zero() *EcPoint {

  return &EcPoint {
    x: big.NewInt(0),
    y: big.NewInt(0),
  }
}


// Returns the curve group generator
func Generator() *EcPoint {
  params := elliptic.P256().Params()

  return &EcPoint{
    x: new(big.Int).Set(params.Gx),
    y: new(big.Int).Set(params.Gy),
  }
}


// Return coordinates in big endian
func (p *EcPoint) ToBytes() ([]byte, []byte) {

  return p.x.Bytes(), p.y.Bytes()
}


// Returns true iff the points are equal componentwise
func (p *EcPoint) IsEqual(p1 *EcPoint) bool {

  return (p.x.Cmp(p1.x) == 0) && (p.y.Cmp(p1.y) == 0)
}


// Return sum of points
func (p *EcPoint) Add(p1 *EcPoint, p2 *EcPoint) *EcPoint {
  x, y := elliptic.P256().Add(p1.x, p1.y, p2.x, p2.y)

  p.x = x
  p.y = y

  return p
}


// Return scalar multiplication
func (p *EcPoint) Mult(scalar *big.Int, pt *EcPoint) *EcPoint {
  x, y := elliptic.P256().ScalarMult(pt.x, pt.y, scalar.Bytes())

  if scalar.Cmp(big.NewInt(0)) < 0 {
    y.Neg(y)
  }

  p.x = x
  p.y = y

  return p
}


// Given scalar s, return s * g
func (p *EcPoint) BaseMult(scalar *big.Int) *EcPoint {
  x, y := elliptic.P256().ScalarBaseMult(scalar.Bytes())

  p.x = x
  p.y = y

  return p
}
