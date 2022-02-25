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
	case PBReq:
		svcMeth = "ConsensusModule.HandlePBReq"
		err := enc.Encode(msg.(PBReq))
		if err != nil {
			log.Fatal(err)
		}
	case PBRes:
		svcMeth = "ConsensusModule.HandlePBRes"
		err := enc.Encode(msg.(PBRes))
		if err != nil {
			log.Fatal(err)
		}
	case PBDone:
		svcMeth = "ConsensusModule.HandlePBDone"
		err := enc.Encode(msg.(PBDone))
		if err != nil {
			log.Fatal(err)
		}
	case EST:
		svcMeth = "ConsensusModule.HandleEST"
		err := enc.Encode(msg.(EST))
		if err != nil {
			log.Fatal(err)
		}
	case AUX:
		svcMeth = "ConsensusModule.HandleAUX"
		err := enc.Encode(msg.(AUX))
		if err != nil {
			log.Fatal(err)
		}
	case CONF:
		svcMeth = "ConsensusModule.HandleCONF"
		err := enc.Encode(msg.(CONF))
		if err != nil {
			log.Fatal(err)
		}
	case COIN:
		svcMeth = "ConsensusModule.HandleCOIN"
		err := enc.Encode(msg.(COIN))
		if err != nil {
			log.Fatal(err)
		}
	case Input:
		svcMeth = "ConsensusModule.HandleInput"
		err := enc.Encode(msg.(Input))
		if err != nil {
			log.Fatal(err)
		}
	case BAInput:
		svcMeth = "ConsensusModule.HandleBAInput"
		err := enc.Encode(msg.(BAInput))
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
