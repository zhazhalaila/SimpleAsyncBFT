package consensus

import (
	"SimpleAsyncBFT/connector"
	"SimpleAsyncBFT/keygen/decodekeys"
	merkletree "SimpleAsyncBFT/merkleTree"
	"SimpleAsyncBFT/message"
	"encoding/json"
	"log"
	"sync"

	"github.com/klauspost/reedsolomon"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type ConsensusModule struct {
	mu     sync.Mutex                    // Prevent data race.
	id     int                           // Peer identify.
	n      int                           // Peers number.
	f      int                           // Byzantine node number.
	logger *log.Logger                   // Log info.
	cs     *connector.ConnectService     // Connector manager.
	suite  *bn256.Suite                  // Suite to crypto.
	pubKey *share.PubPoly                // Threshold signature public key.
	priKey *share.PriShare               // Threshold signature private key.
	round  int                           // Execute round.
	prs    map[int]map[int]*PRBC         // Record prbc for each round.
	prOuts map[int]map[int]PRBCOut       // Result of prbc.
	proofs map[int]map[int]message.Proof // Received proof for each round.
	pbs    map[int]map[int]map[int]*PB   // Record pb for each round, each epoch.
	bas    map[int]*BA                   // Record ba for each round.
	baReqs map[int][]interface{}         // Record baReqs for each round.
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
	cm.prOuts = make(map[int]map[int]PRBCOut)
	cm.proofs = make(map[int]map[int]message.Proof)
	cm.pbs = make(map[int]map[int]map[int]*PB)
	cm.bas = make(map[int]*BA)
	cm.baReqs = make(map[int][]interface{})
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
	cm.PRBCCheck(cm.round, cm.id, rootHash)

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

	cm.PRBCCheck(val.Round, val.Proposer, val.RootHash)
	cm.prs[val.Round][val.Proposer].ValHandler(val)
}

func (cm *ConsensusModule) HandleEcho(echo message.Echo) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] handle echo from [sender:%d].\n", echo.Round, cm.id, echo.Sender)

	cm.PRBCCheck(echo.Round, echo.Proposer, echo.RootHash)
	cm.prs[echo.Round][echo.Proposer].EchoHandler(echo)
}

func (cm *ConsensusModule) HandleReady(ready message.Ready) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] handle ready from [sender:%d].\n", ready.Round, cm.id, ready.Sender)

	cm.PRBCCheck(ready.Round, ready.Proposer, ready.RootHash)
	cm.prs[ready.Round][ready.Proposer].ReadyHandler(ready)
}

func (cm *ConsensusModule) HandleRBCProof(proof message.RBCProof) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] handle proof from [endorser:%d].\n", proof.Round, cm.id, proof.Endorser)

	cm.PRBCCheck(proof.Round, proof.Proposer, proof.RootHash)
	cm.prs[proof.Round][proof.Proposer].ProofHandler(proof)
}

func (cm *ConsensusModule) HandleFinish(fin message.Finish) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] handle finish from [Leader:%d].\n", fin.Round, cm.id, fin.LeaderId)

	cm.PRBCCheck(fin.Round, fin.Proposer, fin.RootHash)
	cm.prs[fin.Round][fin.Proposer].FinishHandler(fin)
}

func (cm *ConsensusModule) HandlePBReq(pbReq message.PBReq) {
	cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] handle pbReq from [Leader:%d].\n",
		pbReq.Round, pbReq.Epoch, cm.id, pbReq.Proposer)

	cm.PBCheck(pbReq.Round, pbReq.Epoch, pbReq.Proposer)

	cm.mu.Lock()
	cm.pbs[pbReq.Round][pbReq.Epoch][pbReq.Proposer].ProofReqHandler(cm.proofs[pbReq.Round], pbReq)
	cm.mu.Unlock()
}

func (cm *ConsensusModule) HandlePBRes(pbRes message.PBRes) {
	cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] handle pbRes from [Endorser:%d].\n",
		pbRes.Round, pbRes.Epoch, cm.id, pbRes.Endorser)

	cm.PBCheck(pbRes.Round, pbRes.Epoch, pbRes.Endorser)

	cm.pbs[pbRes.Round][pbRes.Epoch][pbRes.Proposer].ProofResHandler(pbRes)
}

func (cm *ConsensusModule) HandlePBDone(pd message.PBDone) {
	cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] handle pbDone from [Leader:%d].\n",
		pd.Round, pd.Epoch, cm.id, pd.Proposer)

	cm.PBCheck(pd.Round, pd.Epoch, pd.Proposer)

	cm.pbs[pd.Round][pd.Epoch][pd.Proposer].ProofDoneHandler(pd)
}

func (cm *ConsensusModule) HandleBAInput(in message.BAInput) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] handle BAInput.\n", cm.round, cm.id)

	cm.mu.Lock()
	cm.bas[cm.round] = MakeBA(cm.n, cm.f, cm.id, cm.round, in.EST, cm.logger, cm.cs, cm.suite, cm.pubKey, cm.priKey)
	cm.mu.Unlock()

	go func() {
		value := <-cm.bas[cm.round].decide
		cm.logger.Printf("[Round:%d]: [Peer:%d] get [%d] from ba.\n", cm.round, cm.id, value)
	}()

	for _, req := range cm.baReqs[cm.round] {
		switch v := req.(type) {
		case message.EST:
			cm.bas[cm.round].ESTHandler(req.(message.EST))
		case message.AUX:
			cm.bas[cm.round].AUXHandler(req.(message.AUX))
		case message.CONF:
			cm.bas[cm.round].ConfHandler(req.(message.CONF))
		default:
			cm.logger.Printf("[Round:%d] receive unknown [%v] type in BA.\n", cm.round, v)
		}
	}
}

// If BA has not created, cache req.
func (cm *ConsensusModule) HandleEST(est message.EST) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, ok := cm.bas[est.Round]; ok {
		cm.bas[est.Round].ESTHandler(est)
	} else {
		cm.baReqs[est.Round] = append(cm.baReqs[est.Round], est)
	}
}

func (cm *ConsensusModule) HandleAUX(aux message.AUX) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, ok := cm.bas[aux.Round]; ok {
		cm.bas[aux.Round].AUXHandler(aux)
	} else {
		cm.baReqs[aux.Round] = append(cm.baReqs[aux.Round], aux)
	}
}

func (cm *ConsensusModule) HandleCONF(conf message.CONF) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, ok := cm.bas[conf.Round]; ok {
		cm.bas[conf.Round].ConfHandler(conf)
	} else {
		cm.baReqs[conf.Round] = append(cm.baReqs[conf.Round], conf)
	}
}

func (cm *ConsensusModule) HandleCOIN(coin message.COIN) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, ok := cm.bas[coin.Round]; ok {
		cm.bas[coin.Round].CoinHandler(coin)
	} else {
		cm.baReqs[coin.Round] = append(cm.baReqs[coin.Round], coin)
	}
}

func (cm *ConsensusModule) proofCheck(round int) {
	// Check proof status. If round r proof not init, init proof for round r.
	if _, ok := cm.proofs[round]; !ok {
		cm.proofs[round] = make(map[int]message.Proof)
	}
}

func (cm *ConsensusModule) PRBCCheck(round, proposer int, rootHash []byte) {
	/*
		Check PRBC status.
		If round r prbcs not init, init prbcs for round r.
		If prbc for round r not init, init prbc.
	*/
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, ok := cm.prs[round]; !ok {
		cm.prs[round] = make(map[int]*PRBC)
		cm.prOuts[round] = make(map[int]PRBCOut)
	}

	if _, ok := cm.prs[round][proposer]; !ok {
		cm.prs[round][proposer] = MakePRBC(cm.n,
			cm.f,
			cm.id,
			round,
			proposer,
			rootHash,
			cm.logger,
			cm.cs,
			cm.suite,
			cm.pubKey,
			cm.priKey)
		// Channel monitor.
		go cm.prbcChanMonitor(round, proposer)
	}
}

// PRBC channel will have two monitor. One for wait n-f prbc, one for wait pb.
// Once monitor receive channel value, close it to notify the other monitor exit.
func (cm *ConsensusModule) prbcChanMonitor(round, proposer int) {
	prOut, ok := <-cm.prs[round][proposer].done
	if ok {
		cm.logger.Printf("[Round:%d] [Peer:%d] receive prbc done from [%d].\n", cm.round, cm.id, proposer)
		close(cm.prs[round][proposer].done)
		go cm.waitForPRBC(round, proposer, prOut)
	} else {
		cm.logger.Printf("[Round:%d] has been done.\n", round)
	}
}

func (cm *ConsensusModule) waitForPRBC(round, proposer int, prOut PRBCOut) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.proofCheck(round)

	cm.prOuts[round][proposer] = prOut

	// Wait for n-f prbc out. If prbc out not record in proofs, record it.
	if len(cm.prOuts[round]) == 2*cm.f+1 {
		proofs := make(map[int]message.Proof)
		for id, prOut := range cm.prOuts[round] {
			proofs[id] = message.Proof{
				RootHash:  prOut.rootHash,
				Signature: prOut.rbcSig,
			}
			if _, ok := cm.proofs[round][id]; !ok {
				cm.proofs[round][id] = proofs[id]
			}
		}
		// Generate pbReq msg.
		pbReq := message.PBReq{
			Proposer:  cm.id,
			Round:     cm.round,
			Epoch:     0,
			Proofs:    proofs,
			ProofHash: message.ConvertStructToHashBytes(proofs),
		}
		// Encode pbReq msg.
		pbReqMsg := message.MessageEncode(pbReq)
		// Broadcast pbReq msg.
		cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] broadcast pbReq.\n", cm.round, 0, cm.id)
		cm.cs.Broadcast(pbReqMsg)
	}
}

// Init PB for current {round, epoch, proposer.}
func (cm *ConsensusModule) PBCheck(round, epoch, proposer int) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, ok := cm.pbs[round]; !ok {
		cm.pbs[round] = make(map[int]map[int]*PB)
	}

	if _, ok := cm.pbs[round][epoch]; !ok {
		cm.pbs[round][epoch] = make(map[int]*PB)
	}

	if _, ok := cm.pbs[round][epoch][proposer]; !ok {
		cm.pbs[round][epoch][proposer] = MakePB(
			cm.n,
			cm.f,
			cm.id,
			round,
			epoch,
			proposer,
			cm.logger,
			cm.cs,
			cm.suite,
			cm.pubKey,
			cm.priKey)
		go cm.pbChanMonitor(round, epoch, proposer)
	}
}

// Read from pb channel for current {round, epoch, proposer}.
func (cm *ConsensusModule) pbChanMonitor(round, epoch, proposer int) {
	_, ok := <-cm.pbs[round][epoch][proposer].done
	if ok {
		cm.logger.Printf("[Round:%d] [Epoch:%d] receive pr out from [%d] proposer.\n", round, epoch, proposer)
	}
}

func (cm *ConsensusModule) checkErr(err error) {
	if err != nil {
		cm.logger.Fatal(err)
	}
}

/*
	Skip current round.
	for i := 0; i < n; i++ {
		cm.prs[round][i].lock()
		cm.prs[round][i].skip = true
		cm.prs[round][i].unlock()
		close(cm.prs[round][i].done)
	}
*/
