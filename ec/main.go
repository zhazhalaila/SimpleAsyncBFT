package main

import (
	merkletree "SimpleAsyncBFT/merkleTree"
	"fmt"
	"log"
	"os"
)

func main() {
	var s [][]byte
	s = append(s, []byte("h"))
	s = append(s, []byte("e"))
	s = append(s, []byte("l"))
	mt, err := merkletree.MakeMerkleTree(s)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(mt))

	for i := 0; i < len(s); i++ {
		val := s[i]
		// val = append(val, 's')
		branch := merkletree.GetMerkleBranch(i, mt)
		fmt.Println(merkletree.MerkleTreeVerify(len(s), val, mt[1], branch, i))
	}
	// n := 2
	// k := 2

	// s := "Hello World"
	// strBytes, err := json.Marshal(s)
	// checkErr(err)

	// fmt.Printf("Origin byte array = %v, len = %d (n=%d, k=%d).\n", strBytes, len(strBytes), n, k)
	// var str string
	// err = json.Unmarshal(strBytes, &str)
	// checkErr(err)
	// fmt.Println(str)

	// enc, err := reedsolomon.New(n, k)
	// checkErr(err)
	// shards, err := enc.Split(strBytes)
	// checkErr(err)
	// fmt.Printf("Fill shards = %v.\n", shards)

	// mt, err := merkletree.MakeMerkleTree(shards)
	// checkErr(err)
	// fmt.Println(mt)

	// err = enc.Encode(shards)
	// checkErr(err)
	// fmt.Printf("Encode shards = %v.\n", shards)

	// var blocks [][]byte
	// blocks = append(blocks, shards[0])
	// blocks = append(blocks, nil)
	// blocks = append(blocks, nil)
	// blocks = append(blocks, shards[3])
	// fmt.Printf("Receive blocks = %v.\n", blocks)

	// err = enc.Reconstruct(blocks)
	// checkErr(err)
	// fmt.Printf("Reconstruct data = %v.\n", blocks)
	//
	// fmt.Printf("Origin byte array = %v, len = %d (n=%d, k=%d).\n", strBytes, len(strBytes), n, k)

	// padlen := k - (len(strBytes) % k)
	// for i := 0; i < padlen; i++ {
	// 	strBytes = append(strBytes, byte(k-padlen))
	// }

	// step := len(strBytes) / k
	// var blocks [][]byte
	// for i := 0; i < k; i++ {
	// 	blocks = append(blocks, strBytes[i*step:(i+1)*step])
	// }

	// var placeHolder []byte
	// for i := 0; i < len(blocks[0]); i++ {
	// 	placeHolder = append(placeHolder, 0)
	// }

	// for j := k; j < n+k; j++ {
	// 	blocks = append(blocks, placeHolder)
	// }

	// enc, err := reedsolomon.New(n, k)
	// checkErr(err)
	// err = enc.Encode(blocks)
	// checkErr(err)

	// fmt.Printf("Fill byte array = %v.\n", blocks)
	// _, err = enc.Verify(blocks)
	// checkErr(err)
	// enc, err := reedsolomon.New(n, k)
	// checkErr(err)
	// shards, err := enc.Split(strBytes)
	// checkErr(err)

	// fmt.Printf("Split byte array = %v.\n", shards)

	// err = enc.Encode(shards)
	// checkErr(err)
	// fmt.Printf("Encode byte array = %v.\n", shards)

	// shards[1] = nil
	// shards[2] = nil
	// err = enc.Reconstruct(shards)
	// checkErr(err)
	// fmt.Printf("Decode byte array = %v.\n", shards)
	// // var blocks [][]byte
	// padlen := k - (len(strBytes) % k)
	// for i := 0; i < padlen; i++ {
	// 	strBytes = append(strBytes, byte(k-padlen))
	// }

	// step := len(strBytes) / k
	// var blocks [][]byte
	// for i := 0; i < k; i++ {
	// 	blocks = append(blocks, strBytes[i*step:(i+1)*step])
	// }
	// var placeHolder []byte
	// for i := 0; i < len(blocks[0]); i++ {
	// 	placeHolder = append(placeHolder, byte(0))
	// }

	// for j := k; j < n+k; j++ {
	// 	blocks = append(blocks, placeHolder)
	// }
	// fmt.Printf("Origin blocks = %v.\n", blocks)
	// enc, err := reedsolomon.New(n, k)
	// checkErr(err)

	// err = enc.Encode(blocks)
	// checkErr(err)
	// fmt.Printf("Encode blocks = %v.\n", blocks)

	// blocks[0] = nil

	// fmt.Printf("Missing data blocks = %v.\n", blocks)
	// err = enc.Reconstruct(blocks)
	// checkErr(err)

	// fmt.Printf("Reconstruct data blocks = %v.\n", blocks)
}

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", err.Error())
		os.Exit(2)
	}
}
