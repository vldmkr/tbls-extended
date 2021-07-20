package main

import (
	"encoding/hex"
	"testing"

	"tbls-extended/kyber/v3"
	"tbls-extended/kyber/v3/pairing/bn256"
	"tbls-extended/kyber/v3/share"
	"tbls-extended/kyber/v3/sign/bls"
	"tbls-extended/kyber/v3/sign/tbls"

	"github.com/stretchr/testify/require"
)

func fromHex(s string) []byte {
	decoded, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return decoded
}

func fillBytes(bytes []byte) [32]byte {
	var value [32]byte
	copy(value[:], bytes)
	return value
}

func TestClassicTBLS(test *testing.T) {
	N := 4
	T := 2
	msg := fromHex("a311dfa546baf3b268feeab16bfb57794e88c43a151612f1d095c95fb4f1d2a3")
	seed := fromHex("7d36c0ac7cbe737187823fbc40729fec2ba719f61d2af71f9e8224ecc200e295")

	suite := bn256.NewSuite()
	secret := suite.G1().Scalar().SetBytes(seed)

	priPoly := share.NewPriPoly(suite.G2(), T, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G2().Point().Base())

	sigShares := make([][]byte, 0)
	for i, x := range priPoly.Shares(N) {
		sig, err := tbls.Sign(suite, x, msg)
		require.Nil(test, err)
		sigShares = append(sigShares, sig)
		test.Logf("Share     %d: %x", i, x.I)
		test.Logf("Signature %d: %x", i, sig)
	}
	sig, err := tbls.Recover(suite, pubPoly, msg, sigShares, T, N)
	require.Nil(test, err)
	test.Logf("Group Signature: %x", sig)
	err = bls.Verify(suite, pubPoly.Commit(), msg, sig)
	require.Nil(test, err)
}

func TestExtendedTBLS(test *testing.T) {
	N := 4
	T := 2
	msg := fromHex("a311dfa546baf3b268feeab16bfb57794e88c43a151612f1d095c95fb4f1d2a3")
	seed := fromHex("7d36c0ac7cbe737187823fbc40729fec2ba719f61d2af71f9e8224ecc200e295")
	coeff1 := fromHex("319f61d2af71f87823fbc40729fe9e8222ecc200e27d36c0ac7cbe737195c2ba")
	identities := make([][32]byte, N)
	identities[0] = fillBytes(fromHex("6294efe91ba0945e0ecb45f406f7dc410a355abe286b9afe4756a3c53bea7da5"))
	identities[1] = fillBytes(fromHex("24ecc200e27d36c0ac7cbe737195c2ba719f61d2af71f87823fbc40729fe9e82"))
	identities[2] = fillBytes(fromHex("16bfb57794e88c95fbc43a151612f1d0958feeab4f1d2aa311dfa546baf3b263"))
	identities[3] = fillBytes(fromHex("8adaa8349ad195bb17b96bd288643a0beaf588667bc35e244c241d25b1f552ce"))

	suite := bn256.NewSuite()
	secret := suite.G1().Scalar().SetBytes(seed)

	priCoeffs := make([]kyber.Scalar, T)
	priCoeffs[0] = secret
	priCoeffs[1] = suite.G2().Scalar().SetBytes(coeff1)

	priPoly := share.CoefficientsToPriPoly(suite.G2(), priCoeffs)
	pubPoly := priPoly.Commit(suite.G2().Point().Base())

	sigShares := make([][]byte, 0)
	for i, x := range identities {
		share := priPoly.Eval(x)
		sig, err := tbls.Sign(suite, share, msg)
		require.Nil(test, err)
		sigShares = append(sigShares, sig)
		test.Logf("Share     %d: %x", i, share.I)
		test.Logf("Signature %d: %x", i, sig)
	}

	sig, err := tbls.Recover(suite, pubPoly, msg, sigShares, T, N)
	require.Nil(test, err)
	test.Logf("Group Signature 0:4: %x", sig)
	sig02, err := tbls.Recover(suite, pubPoly, msg, sigShares[0:2], T, N)
	require.Nil(test, err)
	test.Logf("Group Signature 0:2: %x", sig02)
	sig13, err := tbls.Recover(suite, pubPoly, msg, sigShares[1:3], T, N)
	require.Nil(test, err)
	test.Logf("Group Signature 1:3: %x", sig13)
	sig24, err := tbls.Recover(suite, pubPoly, msg, sigShares[2:4], T, N)
	require.Nil(test, err)
	test.Logf("Group Signature 2:4: %x", sig24)

	require.Equal(test, sig, sig02)
	require.Equal(test, sig, sig13)
	require.Equal(test, sig, sig24)

	err = bls.Verify(suite, pubPoly.Commit(), msg, sig)
	require.Nil(test, err)
}
