package merkletree

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math"
)

func MakeMerkleTree(shards [][]byte) ([][]byte, error) {
	n := len(shards)
	if n < 1 {
		return nil, errors.New("too few shards")
	}
	bottomrow := int(math.Pow(2, math.Ceil(math.Log2(float64(n)))))
	var mt [][]byte
	for i := 0; i < 2*bottomrow; i++ {
		mt = append(mt, nil)
	}

	for i := 0; i < n; i++ {
		x := sha256.Sum256(shards[i])
		mt[bottomrow+i] = x[:]
	}

	for i := bottomrow - 1; i > 0; i-- {
		m := append(mt[i*2], mt[i*2+1]...)
		x := sha256.Sum256(m)
		mt[i] = x[:]
	}

	return mt, nil
}

func GetMerkleBranch(index int, mt [][]byte) [][]byte {
	var res [][]byte
	t := index + (len(mt) >> 1)
	for t > 1 {
		res = append(res, mt[t^1])
		t /= 2
	}
	return res
}

func MerkleTreeVerify(n int, val, rootHash []byte, branch [][]byte, index int) bool {
	tmp := sha256.Sum256(val)
	tIndex := index

	for _, br := range branch {
		var parent []byte
		if tIndex&1 == 1 {
			parent = append(br, tmp[:]...)
		} else {
			parent = append(tmp[:], br...)
		}
		tmp = sha256.Sum256(parent)
		tIndex >>= 1
	}

	if bytes.Equal(tmp[:], rootHash) {
		return true
	} else {
		return false
	}
}
