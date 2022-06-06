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
type Point struct {
  x *big.Int
  y *big.Int
}


// Group generator g
func Generator() *Point {
  params := Curve().Params()

  return &Point{
    x: params.Gx,
    y: params.Gy,
  }
}


// Given a saclar a, return a * g
func ScalarTimesGen(a *big.Int) *Point {
  g := Generator()

  x, y := Curve().ScalarMult(g.x, g.y, a.Bytes())
  return &Point {
    x: x,
    y: y,
  }
}
