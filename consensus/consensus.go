package consensus

import (
	"SimpleAsyncBFT/connector"
	"SimpleAsyncBFT/keygen/decodekeys"
	merkletree "SimpleAsyncBFT/merkleTree"
	"SimpleAsyncBFT/message"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
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
	pbOuts map[int]map[int]map[int]PBOut // Result of pb for each {round, epoch}.
	elects map[int]map[int]*Elect        // Record elect form each {round, epoch}.
	bas    map[int]map[int]*BA           // Record ba for each {round, epoch}. One BA maybe not enough.
	baReqs map[int]map[int][]interface{} // Record baReqs for each round.
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
	cm.pbOuts = make(map[int]map[int]map[int]PBOut)
	cm.elects = make(map[int]map[int]*Elect)
	cm.bas = make(map[int]map[int]*BA)
	cm.baReqs = make(map[int]map[int][]interface{})
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
	cm.mu.Lock()
	cm.PRBCCheck(cm.round, cm.id, rootHash)
	cm.mu.Unlock()

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

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PRBCCheck(val.Round, val.Proposer, val.RootHash)
	cm.prs[val.Round][val.Proposer].ValHandler(val)
}

func (cm *ConsensusModule) HandleEcho(echo message.Echo) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] handle echo from [sender:%d].\n", echo.Round, cm.id, echo.Sender)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PRBCCheck(echo.Round, echo.Proposer, echo.RootHash)
	cm.prs[echo.Round][echo.Proposer].EchoHandler(echo)
}

func (cm *ConsensusModule) HandleReady(ready message.Ready) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] handle ready from [sender:%d].\n", ready.Round, cm.id, ready.Sender)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PRBCCheck(ready.Round, ready.Proposer, ready.RootHash)
	cm.prs[ready.Round][ready.Proposer].ReadyHandler(ready)
}

func (cm *ConsensusModule) HandleRBCProof(proof message.RBCProof) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] handle proof from [endorser:%d].\n", proof.Round, cm.id, proof.Endorser)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PRBCCheck(proof.Round, proof.Proposer, proof.RootHash)
	cm.prs[proof.Round][proof.Proposer].ProofHandler(proof)
}

func (cm *ConsensusModule) HandleFinish(fin message.Finish) {
	cm.logger.Printf("[Round:%d]: [Peer:%d] handle finish from [Leader:%d].\n", fin.Round, cm.id, fin.LeaderId)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PRBCCheck(fin.Round, fin.Proposer, fin.RootHash)
	cm.prs[fin.Round][fin.Proposer].FinishHandler(fin)
}

func (cm *ConsensusModule) HandlePBReq(pbReq message.PBReq) {
	cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] handle pbReq from [Leader:%d].\n",
		pbReq.Round, pbReq.Epoch, cm.id, pbReq.Proposer)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PBCheck(pbReq.Round, pbReq.Epoch, pbReq.Proposer)
	cm.pbs[pbReq.Round][pbReq.Epoch][pbReq.Proposer].ProofReqHandler(cm.proofs[pbReq.Round], pbReq)
}

func (cm *ConsensusModule) HandlePBRes(pbRes message.PBRes) {
	cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] handle pbRes from [Endorser:%d].\n",
		pbRes.Round, pbRes.Epoch, cm.id, pbRes.Endorser)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PBCheck(pbRes.Round, pbRes.Epoch, pbRes.Proposer)
	cm.pbs[pbRes.Round][pbRes.Epoch][pbRes.Proposer].ProofResHandler(pbRes)
}

func (cm *ConsensusModule) HandlePBDone(pd message.PBDone) {
	cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] handle pbDone from [Leader:%d].\n",
		pd.Round, pd.Epoch, cm.id, pd.Proposer)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PBCheck(pd.Round, pd.Epoch, pd.Proposer)
	cm.pbs[pd.Round][pd.Epoch][pd.Proposer].ProofDoneHandler(pd)
}

func (cm *ConsensusModule) HandleElect(electReq message.ElectReq) {
	cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] handle elect msg from [Endorser:%d].\n",
		electReq.Round, electReq.Epoch, cm.id, electReq.Endorser)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.ElectCheck(electReq.Round, electReq.Epoch)

	leaderId, ok := cm.elects[electReq.Round][electReq.Epoch].ElectReqHandler(electReq)
	if ok {
		cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] get [Leader:%d].\n", electReq.Round, electReq.Epoch, cm.id, leaderId)
		if _, ok = cm.pbOuts[electReq.Round][1][leaderId]; ok {
			go cm.BAInput(electReq.Round, electReq.Epoch, leaderId, 1)
		} else {
			go cm.BAInput(electReq.Round, electReq.Epoch, leaderId, 0)
		}
	}
}

func (cm *ConsensusModule) BAInput(round, subround, leaderId, est int) {
	cm.logger.Printf("[Round:%d] [SubRound:%d]: [Peer:%d] input [%d] to BA.\n", round, subround, cm.id, est)

	cm.mu.Lock()
	cm.BACheck(cm.round)
	cm.bas[round][subround] = MakeBA(cm.n, cm.f, cm.id, round, subround, est, cm.logger, cm.cs, cm.suite, cm.pubKey, cm.priKey)
	cm.mu.Unlock()

	go cm.baMonitor(round, subround, leaderId)

	for _, req := range cm.baReqs[round][subround] {
		go func(req interface{}) {
			switch v := req.(type) {
			case message.EST:
				cm.bas[round][subround].ESTHandler(req.(message.EST))
			case message.AUX:
				cm.bas[round][subround].AUXHandler(req.(message.AUX))
			case message.CONF:
				cm.bas[round][subround].ConfHandler(req.(message.CONF))
			case message.COIN:
				cm.bas[round][subround].CoinHandler(req.(message.COIN))
			default:
				cm.logger.Printf("[Round:%d] receive unknown [%T] type in BA.\n", cm.round, v)
			}
		}(req)
	}
}

func (cm *ConsensusModule) baMonitor(round, subround, leaderId int) {
	value := <-cm.bas[round][subround].decide
	cm.logger.Printf("[Round:%d] [SubRound:%d]: [Peer:%d] get [%d] from ba.\n", round, subround, cm.id, value)
	if value == 0 {
		subround++
		go cm.electBroadcast(round, subround)
	} else {
		go cm.roundEnd(round, subround, leaderId)
	}
}

func (cm *ConsensusModule) roundEnd(round, subround, leaderId int) {
	var waitPB chan PBOut
	var proofs map[int]message.Proof

	// If BA output 1, wait for pbouts for leaderId.
	cm.mu.Lock()
	if pbOut, ok := cm.pbOuts[round][1][leaderId]; !ok {
		waitPB = cm.pbs[round][1][leaderId].done
	} else {
		proofs = pbOut.proofs
	}
	cm.mu.Unlock()

	if waitPB != nil {
		if pbOut, ok := <-waitPB; ok {
			proofs = pbOut.proofs
			close(waitPB)
		} else {
			cm.mu.Lock()
			proofs = cm.pbOuts[round][1][leaderId].proofs
			cm.mu.Unlock()
		}
	}

	prbcOuts := make(map[int][]byte)
	prbcWaits := make(map[int]chan PRBCOut)

	// If receive pbouts for leaderId, wait for prbc out in proofs.
	cm.mu.Lock()
	for proposer := range proofs {
		if prOut, ok := cm.prOuts[round][proposer]; ok {
			prbcOuts[proposer] = prOut.rbcOut
		} else {
			prbcWaits[proposer] = cm.prs[round][proposer].done
		}
	}
	cm.mu.Unlock()

	if len(prbcWaits) > 0 {
		for proposer, wait := range prbcWaits {
			if prOut, ok := <-wait; ok {
				prbcOuts[proposer] = prOut.rbcOut
				close(wait)
			} else {
				cm.mu.Lock()
				prbcOuts[proposer] = cm.prOuts[round][proposer].rbcOut
				cm.mu.Unlock()
			}
		}
	}

	// Close all channel to avoid goroutine leak.
	// Close prbc channel. If not receive prbc out, skip prbc and close prbc channel.
	for i := 0; i < cm.n; i++ {
		if _, ok := cm.prOuts[round][i]; !ok {
			cm.prs[round][i].skip = true
			close(cm.prs[round][i].done)
		}
	}

	// Close pb channel.
	for epoch := 0; epoch < 2; epoch++ {
		for proposer := 0; proposer < cm.n; proposer++ {
			if _, ok := cm.pbOuts[round][epoch][proposer]; !ok {
				cm.pbs[round][epoch][proposer].skip = true
				close(cm.pbs[round][epoch][proposer].done)
			}
		}
	}
}

// If BA has not created, cache req.
func (cm *ConsensusModule) HandleEST(est message.EST) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.BACheck(est.Round)

	if _, ok := cm.bas[est.Round][est.SubRound]; ok {
		cm.bas[est.Round][est.SubRound].ESTHandler(est)
	} else {
		cm.baReqs[est.Round][est.SubRound] = append(cm.baReqs[est.Round][est.SubRound], est)
	}
}

func (cm *ConsensusModule) HandleAUX(aux message.AUX) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.BACheck(aux.Round)

	if _, ok := cm.bas[aux.Round][aux.SubRound]; ok {
		cm.bas[aux.Round][aux.SubRound].AUXHandler(aux)
	} else {
		cm.baReqs[aux.Round][aux.SubRound] = append(cm.baReqs[aux.Round][aux.SubRound], aux)
	}
}

func (cm *ConsensusModule) HandleCONF(conf message.CONF) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.BACheck(conf.Round)

	if _, ok := cm.bas[conf.Round][conf.SubRound]; ok {
		cm.bas[conf.Round][conf.SubRound].ConfHandler(conf)
	} else {
		cm.baReqs[conf.Round][conf.SubRound] = append(cm.baReqs[conf.Round][conf.SubRound], conf)
	}
}

func (cm *ConsensusModule) HandleCOIN(coin message.COIN) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.BACheck(coin.Round)

	if _, ok := cm.bas[coin.Round][coin.SubRound]; ok {
		cm.bas[coin.Round][coin.SubRound].CoinHandler(coin)
	} else {
		cm.baReqs[coin.Round][coin.SubRound] = append(cm.baReqs[coin.Round][coin.SubRound], coin)
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
		done := make(chan PRBCOut)
		cm.prs[round][proposer].done = done
		// Channel monitor.
		go cm.prbcChanMonitor(round, proposer, done)
	}
}

// PRBC channel will have two monitor. One for wait n-f prbc, one for wait pb.
// Once monitor receive channel value, close it to notify the other monitor exit.
func (cm *ConsensusModule) prbcChanMonitor(round, proposer int, done chan PRBCOut) {
	fmt.Printf("[Round:%d]: [Peer:%d] monitor [%d] prbc.\n", round, cm.id, proposer)
	prOut, ok := <-done
	if ok {
		cm.logger.Printf("[Round:%d] [Peer:%d] receive prbc done from [%d].\n", round, cm.id, proposer)
		close(done)
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
		cm.provableBroadcast(round, 0, proofs)
	}
}

// Init PB for current {round, epoch, proposer.}
func (cm *ConsensusModule) PBCheck(round, epoch, proposer int) {
	cm.proofCheck(round)

	if _, ok := cm.pbOuts[round]; !ok {
		cm.pbOuts[round] = make(map[int]map[int]PBOut)
	}

	if _, ok := cm.pbOuts[round][epoch]; !ok {
		cm.pbOuts[round][epoch] = make(map[int]PBOut)
	}

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
		done := make(chan PBOut)
		cm.pbs[round][epoch][proposer].done = done
		go cm.pbChanMonitor(round, epoch, proposer, done)
	}
}

// Read from pb channel for current {round, epoch, proposer}.
func (cm *ConsensusModule) pbChanMonitor(round, epoch, proposer int, done chan PBOut) {
	pbOut, ok := <-done
	if ok {
		cm.logger.Printf("[Round:%d] [Epoch:%d] receive pr out from [%d] proposer.\n", round, epoch, proposer)
		go cm.waitForPB(round, epoch, proposer, pbOut)
	}
}

func (cm *ConsensusModule) waitForPB(round, epoch, proposer int, pbOut PBOut) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.pbOuts[round][epoch][proposer] = pbOut

	// If epoch == 0, wait for n-f PB done then start epoch 1 pb.
	// If epoch == 1, wait for n-f PB done then start elect.

	if epoch == 0 {
		if len(cm.pbOuts[round][epoch]) == 2*cm.f+1 {
			cm.provableBroadcast(round, 1, cm.proofs[round])
		}
	}

	if epoch == 1 {
		if len(cm.pbOuts[round][epoch]) == 2*cm.f+1 {
			go cm.electBroadcast(round, 0)
		}
	}
}

func (cm *ConsensusModule) ElectCheck(round, epoch int) {
	if _, ok := cm.elects[round]; !ok {
		cm.elects[round] = make(map[int]*Elect)
	}

	if _, ok := cm.elects[round][epoch]; !ok {
		cm.elects[round][epoch] = MakeElect(cm.n, cm.f, cm.id, round, epoch,
			cm.logger,
			cm.cs,
			cm.suite,
			cm.pubKey,
			cm.priKey)
	}
}

func (cm *ConsensusModule) BACheck(round int) {
	if _, ok := cm.bas[round]; !ok {
		cm.bas[round] = make(map[int]*BA)
		cm.baReqs[round] = make(map[int][]interface{})
	}
}

func (cm *ConsensusModule) provableBroadcast(round, epoch int, proofs map[int]message.Proof) {
	// Generate pbReq msg.
	pbReq := message.PBReq{
		Proposer:  cm.id,
		Round:     round,
		Epoch:     epoch,
		Proofs:    proofs,
		ProofHash: message.ConvertStructToHashBytes(proofs),
	}
	// Encode pbReq msg.
	pbReqMsg := message.MessageEncode(pbReq)
	// Broadcast pbReq msg.
	cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] broadcast pbReq.\n", round, epoch, cm.id)
	go cm.cs.Broadcast(pbReqMsg)
}

func (cm *ConsensusModule) electBroadcast(round, epoch int) {
	// Generate elect msg.
	electReq := message.ElectReq{
		Endorser: cm.id,
		Round:    round,
		Epoch:    epoch,
	}
	elecStr := "Elect-" + strconv.Itoa(round) + "-" + strconv.Itoa(epoch)
	electHash := message.ConvertStructToHashBytes(elecStr)
	share := message.GenShare(electHash, cm.suite, cm.priKey)
	electReq.ElectHash = electHash
	electReq.Share = share
	// Encode elect msg.
	electResMsg := message.MessageEncode(electReq)
	// Broadcast elect msg.
	cm.cs.Broadcast(electResMsg)
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
