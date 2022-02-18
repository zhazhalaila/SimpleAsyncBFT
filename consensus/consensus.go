package consensus

import (
	"SimpleAsyncBFT/connector"
	"SimpleAsyncBFT/keygen/decodekeys"
	merkletree "SimpleAsyncBFT/merkleTree"
	"SimpleAsyncBFT/message"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type ConsensusModule struct {
	mu     sync.Mutex                // Prevent data race.
	id     int                       // Peer identify.
	n      int                       // Peers number.
	f      int                       // Byzantine node number.
	logger *log.Logger               // Log info.
	cs     *connector.ConnectService // Connector manager.
	suite  *bn256.Suite              // Suite to crypto.
	pubKey *share.PubPoly            // Threshold signature public key.
	priKey *share.PriShare           // Threshold signature private key.
	round  int                       // Execute round.
	prs    map[int]map[int]*PRBC     // Record prbc for each round.
	prOuts map[int]map[int]PRBCOut   // Result of prbc.
	bas    map[int]*BA               // Record ba for each round.
}

func MakeConsensusModule(n, f, id int, logger *log.Logger, cs *connector.ConnectService) *ConsensusModule {
	cm := &ConsensusModule{}
	cm.n = n
	cm.f = f
	cm.id = id
	cm.logger = logger
	cm.cs = cs
	cm.suite = bn256.NewSuite()
	cm.pubKey = decodekeys.DecodePubShare(cm.suite, cm.n, cm.f+1)
	cm.priKey = decodekeys.DecodePriShare(cm.suite, cm.n, cm.f+1, cm.id)
	cm.round = 0
	cm.prs = make(map[int]map[int]*PRBC)
	cm.bas = make(map[int]*BA)
	return cm
}

func (cm *ConsensusModule) HandleInput(input message.Input) {
	// Input to bytes.
	inputBytes, err := json.Marshal(input.Txs)
	cm.checkErr(err)

	cm.logger.Println(inputBytes)

	// Erasure code scheme.
	enc, err := reedsolomon.New(cm.f+1, 2*cm.f)
	cm.checkErr(err)
	shards, err := enc.Split(inputBytes)
	cm.checkErr(err)

	// Merkle tree construction.
	mt, err := merkletree.MakeMerkleTree(shards)
	cm.checkErr(err)

	rootHash := mt[1]

	// Input validation.
	cm.PRBCCheck(cm.round, cm.id)

	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.logger.Printf("[Round:%d]: [Peer:%d] broadcast val.\n", cm.round, cm.id)

	go func() {
		for index := 0; index < cm.n; index++ {
			branch := merkletree.GetMerkleBranch(index, mt)
			// Generate val msg.
			valBC := message.Val{
				Proposer: cm.id,
				Round:    cm.round,
				RootHash: rootHash,
				Branch:   branch,
				Shard:    shards[index]}
			// Encode val msg.
			valMsg := message.MessageEncode(valBC)
			cm.cs.SendToPeer(index, valMsg)
		}
	}()
}

func (cm *ConsensusModule) HandleVal(val message.Val) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] handle val from [sender:%d].\n", val.Round, cm.id, val.Proposer)

	cm.PRBCCheck(val.Round, val.Proposer)
	cm.prs[val.Round][val.Proposer].ValHandler(val)
}

func (cm *ConsensusModule) HandleEcho(echo message.Echo) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] handle echo from [sender:%d].\n", echo.Round, cm.id, echo.Sender)

	cm.PRBCCheck(echo.Round, echo.Proposer)
	cm.prs[echo.Round][echo.Proposer].EchoHandler(echo)
}

func (cm *ConsensusModule) HandleReady(ready message.Ready) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] handle ready from [sender:%d].\n", ready.Round, cm.id, ready.Sender)

	cm.PRBCCheck(ready.Round, ready.Proposer)
	cm.prs[ready.Round][ready.Proposer].ReadyHandler(ready)
}

func (cm *ConsensusModule) HandleRBCProof(proof message.RBCProof) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] handle proof from [endorser:%d].\n", proof.Round, cm.id, proof.Endorser)

	cm.PRBCCheck(proof.Round, proof.Proposer)
	cm.prs[proof.Round][proof.Proposer].ProofHandler(proof)
}

func (cm *ConsensusModule) HandleFinish(fin message.Finish) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] handle finish from [Leader:%d].\n", fin.Round, cm.id, fin.LeaderId)

	cm.PRBCCheck(fin.Round, fin.Proposer)
	cm.prs[fin.Round][fin.Proposer].FinishHandler(fin)
}

func (cm *ConsensusModule) HandleBAInput(in message.BAInput) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] handle BAInput.\n", cm.round, cm.id)

	cm.bas[cm.round] = MakeBA(cm.n, cm.f, cm.id, cm.round, in.EST, cm.logger, cm.cs)
}

func (cm *ConsensusModule) HandleEST(est message.EST) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] receive est from [Sender:%d].\n", est.Round, cm.id, est.Sender)

	// Wait for BA input.
	for {
		if _, ok := cm.bas[est.Round]; ok {
			cm.bas[est.Round].ESTHandler(est)
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (cm *ConsensusModule) HandleAUX(aux message.AUX) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] receive aux from [Sender:%d].\n", aux.Round, cm.id, aux.Sender)

	// Wait for BA input.
	for {
		if _, ok := cm.bas[aux.Round]; ok {
			cm.bas[aux.Round].AUXHandler(aux)
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (cm *ConsensusModule) PRBCCheck(round, proposer int) {
	/*
		Check PRBC status.
		If round r prbcs not init, init prbcs for round r.
		If prbc for round r not init, init prbc.
	*/
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, ok := cm.prs[round]; !ok {
		cm.prs[round] = make(map[int]*PRBC)
		cm.prOuts = make(map[int]map[int]PRBCOut)
	}

	if _, ok := cm.prs[round][proposer]; !ok {
		cm.prs[round][proposer] = MakePRBC(cm.n, cm.f, cm.id, round, proposer, cm.logger, cm.cs, cm.suite, cm.pubKey, cm.priKey)
		// Channel monitor.
		go func() {
			prOut := <-cm.prs[round][proposer].done
			cm.logger.Println(prOut)
		}()
	}
}

func (cm *ConsensusModule) checkErr(err error) {
	if err != nil {
		cm.logger.Fatal(err)
	}
}
