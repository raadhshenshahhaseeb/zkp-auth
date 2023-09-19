package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
)

type ZKP struct {
	p     *big.Int
	q     *big.Int
	alpha *big.Int
	beta  *big.Int
}

func (zkp *ZKP) ComputePair(exp *big.Int) (*big.Int, *big.Int) {
	p1 := new(big.Int).Exp(zkp.alpha, exp, zkp.p)
	p2 := new(big.Int).Exp(zkp.beta, exp, zkp.p)
	return p1, p2
}

func (zkp *ZKP) Solve(k, c, x *big.Int) *big.Int {
	if k.Cmp(new(big.Int).Mul(c, x)) >= 0 {
		return new(big.Int).Mod(new(big.Int).Sub(k, new(big.Int).Mul(c, x)), zkp.q)
	}
	return new(big.Int).Sub(zkp.q, new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(c, x), k), zkp.q))
}

func (zkp *ZKP) Verify(r1, r2, y1, y2, c, s *big.Int) bool {
	cond1 := r1.Cmp(new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(zkp.alpha, s, zkp.p), new(big.Int).Exp(y1, c, zkp.p)), zkp.p)) == 0
	cond2 := r2.Cmp(new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(zkp.beta, s, zkp.p), new(big.Int).Exp(y2, c, zkp.p)), zkp.p)) == 0
	return cond1 && cond2
}

func GenerateRandomNumberBelow(bound *big.Int) *big.Int {
	n, _ := rand.Int(rand.Reader, bound)
	return n
}

func GenerateRandomString(size int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, size)
	for i := range b {
		val, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[val.Int64()]
	}
	return string(b)
}

func GetConstants() (*big.Int, *big.Int, *big.Int, *big.Int) {
	pBytes, _ := hex.DecodeString("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371")
	qBytes, _ := hex.DecodeString("F518AA8781A8DF278ABA4E7D64B7CB9D49462353")
	alphaBytes, _ := hex.DecodeString("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5")
	expBytes, _ := hex.DecodeString("266FEA1E5C41564B777E69")

	p := new(big.Int).SetBytes(pBytes)
	q := new(big.Int).SetBytes(qBytes)
	alpha := new(big.Int).SetBytes(alphaBytes)
	beta := new(big.Int).Exp(alpha, new(big.Int).SetBytes(expBytes), p)

	return alpha, beta, p, q
}

func hashWithBlinding(age, r *big.Int) []byte {
	input := append(age.Bytes(), r.Bytes()...)
	hash := sha256.Sum256(input)
	return hash[:]
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("Enter age (or type 'exit' to quit): ")
		scanner.Scan()
		input := scanner.Text()

		if input == "exit" {
			break
		}

		age := new(big.Int)
		age.SetString(input, 10)

		// Choose a random blinding factor
		r, _ := rand.Int(rand.Reader, big.NewInt(1<<62))

		// Compute the commitment
		commitment := hashWithBlinding(age, r)

		// The verifier sends a random challenge
		c, _ := rand.Int(rand.Reader, big.NewInt(1<<62))

		// The user computes the response
		response := new(big.Int).Add(age, new(big.Int).Mul(c, r))

		// The verifier checks the response
		expectedCommitment := hashWithBlinding(response, new(big.Int).Neg(new(big.Int).Mul(c, r)))

		if string(commitment) == string(expectedCommitment) && response.Cmp(big.NewInt(18)) >= 0 {
			fmt.Println("Proof successful: The age is over 18!")
		} else {
			fmt.Println("Proof failed!")
		}
	}
}
