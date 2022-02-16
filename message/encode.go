package message

import (
	"bytes"
	"encoding/gob"
	"log"
)

func MessageEncode(msg interface{}) ReqMsg {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	var svcMeth string

	switch v := msg.(type) {
	case Val:
		svcMeth = "ConsensusModule.HandleVal"
		err := enc.Encode(msg.(Val))
		if err != nil {
			log.Println(err)
		}
	case Echo:
		svcMeth = "ConsensusModule.HandleEcho"
		err := enc.Encode(msg.(Echo))
		if err != nil {
			log.Println(err)
		}
	case Ready:
		svcMeth = "ConsensusModule.HandleReady"
		err := enc.Encode(msg.(Ready))
		if err != nil {
			log.Println(err)
		}
	case RBCProof:
		svcMeth = "ConsensusModule.HandleRBCProof"
		err := enc.Encode(msg.(RBCProof))
		if err != nil {
			log.Fatal(err)
		}
	case Finish:
		svcMeth = "ConsensusModule.HandleFinish"
		err := enc.Encode(msg.(Finish))
		if err != nil {
			log.Fatal(err)
		}
	case Input:
		svcMeth = "ConsensusModule.HandleInput"
		err := enc.Encode(msg.(Input))
		if err != nil {
			log.Fatal(err)
		}
	case ConnectPeer:
		svcMeth = "ConnectService.ConnectOtherPeer"
		err := enc.Encode(msg.(ConnectPeer))
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Println(v)
	}
	reqMsg := ReqMsg{
		SvcMeth: svcMeth,
		Args:    buffer.Bytes(),
	}
	return reqMsg
}
