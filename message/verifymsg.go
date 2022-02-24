package message

import (
	"crypto/sha256"
	"encoding/json"
	"log"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
)

func ConvertStructToHashBytes(s interface{}) []byte {
	converted, err := json.Marshal(s)
	if err != nil {
		log.Println(err)
		return nil
	}
	convertedHash := sha256.Sum256(converted)
	return convertedHash[:]
}

// Generate paitial share.
func GenShare(data []byte, suite *bn256.Suite, priKey *share.PriShare) []byte {
	sig, err := tbls.Sign(suite, priKey, data)
	if err != nil {
		log.Println(err)
		return nil
	}
	return sig
}

func ComputeSignature(data []byte, suite *bn256.Suite, shares [][]byte, pubKey *share.PubPoly, n, t int) []byte {
	signature, err := tbls.Recover(suite, pubKey, data, shares, t, n)
	if err != nil {
		log.Println("Verify tble.Recover")
		log.Println(err)
		return nil
	}
	return signature
}

func SignatureVerify(data []byte, sig []byte, suite *bn256.Suite, pubKey *share.PubPoly) bool {
	err := bls.Verify(suite, pubKey.Commit(), data, sig)
	if err != nil {
		log.Println("Threshold Verify bls.Verify")
		log.Println(err)
		return false
	}
	return true
}

func ShareVerify(data []byte, share []byte, suite *bn256.Suite, pubKey *share.PubPoly) bool {
	err := tbls.Verify(suite, pubKey, data, share)
	if err != nil {
		log.Println("Share Verify tbls.Verify")
		log.Println(err)
		return false
	}
	return true
}
