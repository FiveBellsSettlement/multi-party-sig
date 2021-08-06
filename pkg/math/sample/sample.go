package sample

import (
	"fmt"
	"io"
	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

const maxIterations = 255

var ErrMaxIterations = fmt.Errorf("sample: failed to generate after %d iterations", maxIterations)

func mustReadBits(rand io.Reader, buf []byte) {
	for i := 0; i < maxIterations; i++ {
		if _, err := io.ReadFull(rand, buf); err == nil {
			return
		}
	}
	panic(ErrMaxIterations)
}

// ModN samples an element of ℤₙ.
func ModN(rand io.Reader, n *safenum.Modulus) *safenum.Nat {
	out := new(safenum.Nat)
	buf := make([]byte, (n.BitLen()+7)/8)
	for {
		mustReadBits(rand, buf)
		out.SetBytes(buf)
		_, _, lt := out.CmpMod(n)
		if lt == 1 {
			break
		}
	}
	return out
}

// UnitModN returns a u ∈ ℤₙˣ.
func UnitModN(rand io.Reader, n *safenum.Modulus) *safenum.Nat {
	for i := 0; i < maxIterations; i++ {
		// PERF: Reuse buffer instead of allocating each time
		u := ModN(rand, n)
		if u.IsUnit(n) == 1 {
			return u
		}
	}
	panic(ErrMaxIterations)
}

// QNR samples a random quadratic non-residue in Z_n.
func QNR(rand io.Reader, n *big.Int) *big.Int {
	var w big.Int
	buf := make([]byte, params.BitsIntModN/8)
	for i := 0; i < maxIterations; i++ {
		mustReadBits(rand, buf)
		w.SetBytes(buf)
		w.Mod(&w, n)
		if big.Jacobi(&w, n) == -1 {
			return &w
		}
	}
	panic(ErrMaxIterations)
}

// Pedersen generates the s, t, λ such that s = tˡ.
func Pedersen(rand io.Reader, phi *safenum.Nat, n *safenum.Modulus) (s, t, lambda *safenum.Nat) {
	phiMod := safenum.ModulusFromNat(phi)

	lambda = ModN(rand, phiMod)

	tau := UnitModN(rand, n)
	// t = τ² mod N
	t = tau.ModMul(tau, tau, n)
	// s = tˡ mod N
	s = new(safenum.Nat).Exp(t, lambda, n)

	return
}

// Scalar returns a new *curve.Scalar by reading bytes from rand.
func Scalar(rand io.Reader) *curve.Scalar {
	var s curve.Scalar
	buffer := make([]byte, params.BytesScalar)
	mustReadBits(rand, buffer)
	s.SetBytes(buffer)
	return &s
}

// ScalarUnit returns a new *curve.Scalar by reading bytes from rand.
func ScalarUnit(rand io.Reader) *curve.Scalar {
	for i := 0; i < maxIterations; i++ {
		s := Scalar(rand)
		// Note: This works since our curve has prime order, but you need a more
		// sophisticated check in other situations.
		if !s.IsZero() {
			return s
		}
	}
	panic(ErrMaxIterations)
}

// ScalarPointPair returns a new *curve.Scalar/*curve.Point tuple (x,X) by reading bytes from rand.
// The tuple satisfies X = x⋅G where G is the base point of the curve.
func ScalarPointPair(rand io.Reader) (*curve.Scalar, *curve.Point) {
	var p curve.Point
	s := Scalar(rand)
	p.ScalarBaseMult(s)
	return s, &p
}
