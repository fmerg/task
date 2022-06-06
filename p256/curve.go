package p256

import (
  "crypto/elliptic"
  "math/big"
)


func Curve() elliptic.Curve {

  return elliptic.P256()
}


// order of underlying field
func Order() *big.Int {

  return Curve().Params().P
}


// bit size of underlying field
func BitSize() int {

  return Curve().Params().BitSize
}


// Representation of curve points as (x, y) tuples
type EcPoint struct {
  x *big.Int
  y *big.Int
}


// Return coordinates in big endian
func (pt *EcPoint) ToBytes() ([]byte, []byte) {

  return pt.x.Bytes(), pt.y.Bytes()
}


// Return negative with respect to the group's zero element
func (pt *EcPoint) Neg() *EcPoint {

  return &EcPoint {
    x: new(big.Int).Set(pt.x),
    y: new(big.Int).Neg(pt.y),
  }
}


// Return sum of points
func (pt *EcPoint) Add(other *EcPoint) *EcPoint {
  x, y := Curve().Add(pt.x, pt.y, other.x, other.y)

  return &EcPoint {
    x: x,
    y: y,
  }
}


// Return scalar multiplication
func (pt *EcPoint) ScalarMult(a *big.Int) *EcPoint {
  x, y := Curve().ScalarMult(pt.x, pt.y, a.Bytes())

  if a.Cmp(big.NewInt(0)) < 0 {
    y.Neg(y)
  }

  return &EcPoint {
    x: x,
    y: y,
  }
}


// Group generator g
func Generator() *EcPoint {
  params := Curve().Params()

  return &EcPoint{
    x: new(big.Int).Set(params.Gx),
    y: new(big.Int).Set(params.Gy),
  }
}


// Given a saclar a, return a * g
func ScalarTimesGen(a *big.Int) *EcPoint {
  g := Generator()

  x, y := Curve().ScalarMult(g.x, g.y, a.Bytes())

  return &EcPoint {
    x: new(big.Int).Set(x),
    y: new(big.Int).Set(y),
  }
}
