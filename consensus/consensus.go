package consensus

import (
	"SimpleAsyncBFT/message"
	"fmt"
)

type ConsensusModule struct {
	round int
}

func MakeConsensusModule() *ConsensusModule {
	cm := &ConsensusModule{}
	cm.round = 0
	return cm
}

func (cm *ConsensusModule) HandleProof(proof message.Proof) {
	fmt.Printf("HandleProof....\n")
	fmt.Println(proof)
}

func (cm *ConsensusModule) HandleProofPointer(proof *message.Proof) {
	fmt.Printf("HandleProof pointer...\n")
	fmt.Println(proof)
}
