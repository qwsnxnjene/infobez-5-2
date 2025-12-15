package main

import (
	"crypto/rand"
	"math/big"
)

func SolovayStrassenTest(n *big.Int, iterations int) bool {
	if n.Cmp(big.NewInt(2)) == 0 {
		return true
	}
	if n.Cmp(big.NewInt(2)) < 0 || new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		return false
	}

	for i := 0; i < iterations; i++ {
		max := new(big.Int).Sub(n, big.NewInt(2))
		a, _ := rand.Int(rand.Reader, max)
		a.Add(a, big.NewInt(2))

		x := JacobiSymbol(a, n)
		if x == 0 {
			return false
		}

		// a^((n-1)/2) mod n
		exp := new(big.Int).Sub(n, big.NewInt(1))
		exp.Div(exp, big.NewInt(2))
		y := new(big.Int).Exp(a, exp, n)

		xBig := big.NewInt(int64(x))
		if xBig.Cmp(big.NewInt(0)) < 0 {
			xBig.Add(xBig, n)
		}

		if y.Cmp(xBig) != 0 {
			return false
		}
	}
	return true
}

func JacobiSymbol(a, n *big.Int) int {
	if n.Cmp(big.NewInt(0)) <= 0 || new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		return 0
	}

	a = new(big.Int).Mod(a, n)
	result := 1

	for a.Cmp(big.NewInt(0)) != 0 {
		for new(big.Int).Mod(a, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
			a.Div(a, big.NewInt(2))
			nMod8 := new(big.Int).Mod(n, big.NewInt(8))
			if nMod8.Cmp(big.NewInt(3)) == 0 || nMod8.Cmp(big.NewInt(5)) == 0 {
				result = -result
			}
		}
		a, n = n, a
		if new(big.Int).Mod(a, big.NewInt(4)).Cmp(big.NewInt(3)) == 0 &&
			new(big.Int).Mod(n, big.NewInt(4)).Cmp(big.NewInt(3)) == 0 {
			result = -result
		}
		a = new(big.Int).Mod(a, n)
	}

	if n.Cmp(big.NewInt(1)) == 0 {
		return result
	}
	return 0
}

func MillerRabinTest(n *big.Int, iterations int) bool {
	if n.Cmp(big.NewInt(2)) == 0 || n.Cmp(big.NewInt(3)) == 0 {
		return true
	}
	if n.Cmp(big.NewInt(2)) < 0 || new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		return false
	}

	// n - 1 = 2^r * d
	d := new(big.Int).Sub(n, big.NewInt(1))
	r := 0
	for new(big.Int).Mod(d, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		d.Div(d, big.NewInt(2))
		r++
	}

	for i := 0; i < iterations; i++ {
		max := new(big.Int).Sub(n, big.NewInt(3))
		a, _ := rand.Int(rand.Reader, max)
		a.Add(a, big.NewInt(2))

		x := new(big.Int).Exp(a, d, n)

		if x.Cmp(big.NewInt(1)) == 0 || x.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 {
			continue
		}

		continueLoop := false
		for j := 0; j < r-1; j++ {
			x.Exp(x, big.NewInt(2), n)
			if x.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 {
				continueLoop = true
				break
			}
		}

		if !continueLoop {
			return false
		}
	}
	return true
}

func GeneratePrimeSolovayStrassen(bits int) (*big.Int, error) {
	for {
		n, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, err
		}

		if SolovayStrassenTest(n, 20) {
			return n, nil
		}
	}
}

func GeneratePrimeMillerRabin(bits int) (*big.Int, error) {
	for {
		n, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, err
		}

		if MillerRabinTest(n, 20) {
			return n, nil
		}
	}
}

func FindPrimitiveRoot(p *big.Int) (*big.Int, error) {
	// q = (p-1)/2
	q := new(big.Int).Sub(p, big.NewInt(1))
	q.Div(q, big.NewInt(2))

	for {
		g, err := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))
		if err != nil {
			return nil, err
		}
		g.Add(g, big.NewInt(2))

		// g^2 mod p != 1 и g^q mod p != 1
		test1 := new(big.Int).Exp(g, big.NewInt(2), p)
		test2 := new(big.Int).Exp(g, q, p)

		if test1.Cmp(big.NewInt(1)) != 0 && test2.Cmp(big.NewInt(1)) != 0 {
			return g, nil
		}
	}
}

func GenerateOddNumber(bits int) (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	if err != nil {
		return nil, err
	}

	n.Or(n, big.NewInt(1))
	return n, nil
}

func ExtendedGCD(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	if b.Cmp(big.NewInt(0)) == 0 {
		return new(big.Int).Set(a), big.NewInt(1), big.NewInt(0)
	}

	gcd, x1, y1 := ExtendedGCD(b, new(big.Int).Mod(a, b))

	x := new(big.Int).Set(y1)
	y := new(big.Int).Sub(x1, new(big.Int).Mul(new(big.Int).Div(a, b), y1))

	return gcd, x, y
}

func ModInverse(a, m *big.Int) *big.Int {
	gcd, x, _ := ExtendedGCD(a, m)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil
	}

	result := new(big.Int).Mod(x, m)
	if result.Cmp(big.NewInt(0)) < 0 {
		result.Add(result, m)
	}
	return result
}
