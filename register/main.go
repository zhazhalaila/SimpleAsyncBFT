package main

import (
	"SimpleAsyncBFT/message"
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
)

func main() {
	conn, err := net.Dial("tcp", ":8000")
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	defer conn.Close()

	var buffer bytes.Buffer
	msg := message.Proof{Sender: 100, Proof: "Hello"}
	enc := gob.NewEncoder(&buffer)
	err = enc.Encode(msg)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	msgMeta := message.ReqMsg{
		SvcMeth: "ConsensusModule.HandleProofPointer",
		Args:    buffer.Bytes(),
	}

	fmt.Println(msgMeta)

	msgMetaJs, err := json.Marshal(msgMeta)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(msgMetaJs))

	conn.Write(msgMetaJs)
}
