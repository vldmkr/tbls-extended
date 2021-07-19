package as

import (
	"testing"

	"tbls-extended/kyber/v3/pairing/bn256"
	"tbls-extended/kyber/v3/share"
	"tbls-extended/kyber/v3/sign/bls"
	"tbls-extended/kyber/v3/sign/tbls"

	"github.com/stretchr/testify/require"
)

func TestTBLS(test *testing.T) {
	var err error
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	n := 10
	t := n/2 + 1
	secret := suite.G1().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G2(), t, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	sigShares := make([][]byte, 0)
	for _, x := range priPoly.Shares(n) {
		sig, err := tbls.Sign(suite, x, msg)
		require.Nil(test, err)
		sigShares = append(sigShares, sig)
	}
	sig, err := tbls.Recover(suite, pubPoly, msg, sigShares, t, n)
	require.Nil(test, err)
	err = bls.Verify(suite, pubPoly.Commit(), msg, sig)
	require.Nil(test, err)
}
