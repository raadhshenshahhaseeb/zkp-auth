package main

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestToyExample(t *testing.T) {
	alpha := big.NewInt(4)
	beta := big.NewInt(9)
	p := big.NewInt(23)
	q := big.NewInt(11)
	zkp := ZKP{
		p:     p,
		q:     q,
		alpha: alpha,
		beta:  beta,
	}

	x := big.NewInt(6)
	k := big.NewInt(7)
	c := big.NewInt(4)

	y1, y2 := zkp.ComputePair(x)
	if y1.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("Expected y1 to be 2, but got %s", y1.String())
	}
	if y2.Cmp(big.NewInt(3)) != 0 {
		t.Errorf("Expected y2 to be 3, but got %s", y2.String())
	}

	r1, r2 := zkp.ComputePair(k)
	if r1.Cmp(big.NewInt(8)) != 0 {
		t.Errorf("Expected r1 to be 8, but got %s", r1.String())
	}
	if r2.Cmp(big.NewInt(4)) != 0 {
		t.Errorf("Expected r2 to be 4, but got %s", r2.String())
	}

	s := zkp.Solve(k, c, x)
	if s.Cmp(big.NewInt(5)) != 0 {
		t.Errorf("Expected s to be 5, but got %s", s.String())
	}

	result := zkp.Verify(r1, r2, y1, y2, c, s)
	if !result {
		t.Errorf("Expected verification to be true, but got false")
	}

	// fake secret
	xFake := big.NewInt(7)
	sFake := zkp.Solve(k, c, xFake)

	result = zkp.Verify(r1, r2, y1, y2, c, sFake)
	if result {
		t.Errorf("Expected verification to be false with fake secret, but got true")
	}
}

func TestToyExampleWithRandomNumbers(t *testing.T) {
	alpha := big.NewInt(4)
	beta := big.NewInt(9)
	p := big.NewInt(23)
	q := big.NewInt(11)
	zkp := ZKP{
		p:     p,
		q:     q,
		alpha: alpha,
		beta:  beta,
	}

	x := big.NewInt(6)
	k := GenerateRandomNumberBelow(q)
	c := GenerateRandomNumberBelow(q)

	y1, y2 := zkp.ComputePair(x)
	if y1.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("Expected y1 to be 2, but got %s", y1.String())
	}
	if y2.Cmp(big.NewInt(3)) != 0 {
		t.Errorf("Expected y2 to be 3, but got %s", y2.String())
	}

	r1, r2 := zkp.ComputePair(k)
	s := zkp.Solve(k, c, x)

	result := zkp.Verify(r1, r2, y1, y2, c, s)
	if !result {
		t.Errorf("Expected verification to be true, but got false")
	}
}

func Test1024BitsConstants(t *testing.T) {
	// ... (hexadecimal values for p, q, and alpha as in the provided Rust code) ...

	pBytes, _ := hex.DecodeString("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371")
	qBytes, _ := hex.DecodeString("F518AA8781A8DF278ABA4E7D64B7CB9D49462353")
	alphaBytes, _ := hex.DecodeString("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5")

	p := new(big.Int).SetBytes(pBytes)
	q := new(big.Int).SetBytes(qBytes)
	alpha := new(big.Int).SetBytes(alphaBytes)

	// beta = alpha^i is also a generator
	beta := new(big.Int).Exp(alpha, GenerateRandomNumberBelow(q), p)

	zkp := ZKP{
		p:     p,
		q:     q,
		alpha: alpha,
		beta:  beta,
	}

	x := GenerateRandomNumberBelow(q)
	k := GenerateRandomNumberBelow(q)
	c := GenerateRandomNumberBelow(q)

	y1, y2 := zkp.ComputePair(x)
	r1, r2 := zkp.ComputePair(k)
	s := zkp.Solve(k, c, x)

	result := zkp.Verify(r1, r2, y1, y2, c, s)
	if !result {
		t.Errorf("Expected verification to be true, but got false")
	}
}
