package consensus

import (
	"SimpleAsyncBFT/connector"
	"SimpleAsyncBFT/keygen/decodekeys"
	merkletree "SimpleAsyncBFT/merkleTree"
	"SimpleAsyncBFT/message"
	"encoding/json"
	"log"
	"strconv"

	"github.com/klauspost/reedsolomon"
	"github.com/sasha-s/go-deadlock"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type ConsensusModule struct {
	mu       deadlock.Mutex                // Prevent data race.
	id       int                           // Peer identify.
	n        int                           // Peers number.
	f        int                           // Byzantine node number.
	logger   *log.Logger                   // Log info.
	cs       *connector.ConnectService     // Connector manager.
	suite    *bn256.Suite                  // Suite to crypto.
	pubKey   *share.PubPoly                // Threshold signature public key.
	priKey   *share.PriShare               // Threshold signature private key.
	round    int                           // Execute round.
	reqs     map[int]message.ClientRequest // Record client requests.
	prbcs    map[int]map[int]*PRBC         // Record prbc for each round.
	prbcOuts map[int]map[int]PRBCOut       // Result of prbc.
	proofs   map[int]map[int]message.Proof // Received proof for each round.
	pbs      map[int]map[int]map[int]*PB   // Record pb for each round, each epoch.
	pbOuts   map[int]map[int]map[int]PBOut // Result of pb for each {round, epoch}.
	elects   map[int]map[int]*Elect        // Record elect form each {round, epoch}.
	bas      map[int]map[int]*BA           // Record ba for each {round, epoch}. One BA maybe not enough.
	baReqs   map[int]map[int][]interface{} // Record baReqs for each {round, epoch}.
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
	cm.reqs = make(map[int]message.ClientRequest)
	cm.prbcs = make(map[int]map[int]*PRBC)
	cm.prbcOuts = make(map[int]map[int]PRBCOut)
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

	// Erasure code scheme.
	enc, err := reedsolomon.New(cm.f+1, cm.n-(cm.f+1))
	cm.checkErr(err)
	shards, err := enc.Split(inputBytes)
	cm.checkErr(err)

	// Merkle tree construction.
	mt, err := merkletree.MakeMerkleTree(shards)
	cm.checkErr(err)

	rootHash := mt[1]

	// Input validation.
	cm.mu.Lock()
	cm.reqs[cm.round] = input.ClientReq
	cm.PRBCCheck(cm.round, cm.id, rootHash)
	round := cm.round
	cm.round++
	cm.mu.Unlock()

	// cm.logger.Printf("[Round:%d]: [Peer:%d] start PRBC.\n", round, cm.id)

	go func(round int) {
		for index := 0; index < cm.n; index++ {
			branch := merkletree.GetMerkleBranch(index, mt)
			// Generate val msg.
			valBC := message.Val{
				Proposer: cm.id,
				Round:    round,
				RootHash: rootHash,
				Branch:   branch,
				Shard:    shards[index]}
			// Encode val msg.
			valMsg := message.MessageEncode(valBC)
			cm.cs.SendToPeer(index, valMsg)
		}
	}(round)
}

func (cm *ConsensusModule) HandleVal(val message.Val) {
	// // cm.logger.Printf("[Round:%d]: [Peer:%d] handle val from [sender:%d].\n", val.Round, cm.id, val.Proposer)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PRBCCheck(val.Round, val.Proposer, val.RootHash)
	cm.prbcs[val.Round][val.Proposer].ValHandler(val)
}

func (cm *ConsensusModule) HandleEcho(echo message.Echo) {
	// // cm.logger.Printf("[Round:%d]: [Peer:%d] handle echo from [sender:%d].\n", echo.Round, cm.id, echo.Sender)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PRBCCheck(echo.Round, echo.Proposer, echo.RootHash)
	cm.prbcs[echo.Round][echo.Proposer].EchoHandler(echo)
}

func (cm *ConsensusModule) HandleReady(ready message.Ready) {
	// // cm.logger.Printf("[Round:%d]: [Peer:%d] handle ready from [sender:%d].\n", ready.Round, cm.id, ready.Sender)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PRBCCheck(ready.Round, ready.Proposer, ready.RootHash)
	cm.prbcs[ready.Round][ready.Proposer].ReadyHandler(ready)
}

func (cm *ConsensusModule) HandleRBCProof(proof message.RBCProof) {
	// // cm.logger.Printf("[Round:%d]: [Peer:%d] handle proof from [endorser:%d].\n", proof.Round, cm.id, proof.Endorser)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PRBCCheck(proof.Round, proof.Proposer, proof.RootHash)
	cm.prbcs[proof.Round][proof.Proposer].ProofHandler(proof)
}

func (cm *ConsensusModule) HandleFinish(fin message.Finish) {
	// // cm.logger.Printf("[Round:%d]: [Peer:%d] handle finish from [Leader:%d].\n", fin.Round, cm.id, fin.LeaderId)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PRBCCheck(fin.Round, fin.Proposer, fin.RootHash)
	cm.prbcs[fin.Round][fin.Proposer].FinishHandler(fin)
}

func (cm *ConsensusModule) PRBCCheck(round, proposer int, rootHash []byte) {
	/*
		Check PRBC status.
		If round r prbcs not init, init prbcs for round r.
		If prbc for round r not init, init prbc.
	*/
	if _, ok := cm.prbcs[round]; !ok {
		cm.prbcs[round] = make(map[int]*PRBC)
		cm.prbcOuts[round] = make(map[int]PRBCOut)
	}

	// Channel is reference type, create channel from outside to monitor channel.
	if _, ok := cm.prbcs[round][proposer]; !ok {
		cm.prbcs[round][proposer] = MakePRBC(cm.n,
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
		cm.prbcs[round][proposer].done = done
		// Channel monitor.
		go cm.prbcChanMonitor(round, proposer, done)
	}
}

// PRBC channel will have two monitor. One for wait n-f prbc, one for wait pb.
// Once monitor receive channel value, close it to notify the other monitor exit.
func (cm *ConsensusModule) prbcChanMonitor(round, proposer int, done chan PRBCOut) {
	// // cm.logger.Printf("[Round:%d]: [Peer:%d] monitor [%d] prbc.\n", round, cm.id, proposer)
	prbcOut, ok := <-done
	if ok {
		// cm.logger.Printf("[Round:%d] [Peer:%d] receive prbc done from [%d].\n", round, cm.id, proposer)
		cm.waitForPRBC(round, proposer, prbcOut, done)
	} else {
		// cm.logger.Printf("[Round:%d] [Proposer:%d] prbc has been done [RoundEnd!].\n", round, proposer)
	}
}

func (cm *ConsensusModule) waitForPRBC(round, proposer int, prbcOut PRBCOut, done chan PRBCOut) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.prbcs[round][proposer].Skipped() {
		return
	}

	cm.proofCheck(round)

	// Store prbc output and close channel.
	cm.prbcOuts[round][proposer] = prbcOut
	cm.prbcs[round][proposer].Skip()
	close(done)
	// Wait for n-f prbc out. If prbc out not record in proofs, record it.
	if len(cm.prbcOuts[round]) == 2*cm.f+1 {
		proofs := make(map[int]message.Proof)
		for proposer, prbcOut := range cm.prbcOuts[round] {
			proofs[proposer] = message.Proof{
				RootHash:  prbcOut.rootHash,
				Signature: prbcOut.rbcSig,
			}
			if _, ok := cm.proofs[round][proposer]; !ok {
				cm.proofs[round][proposer] = proofs[proposer]
			}
		}
		cm.provableBroadcast(round, 0, proofs)
	}
}

func (cm *ConsensusModule) HandlePBReq(pbReq message.PBReq) {
	// // cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] handle pbReq from [Leader:%d].\n",
	// 	pbReq.Round, pbReq.Epoch, cm.id, pbReq.Proposer)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PBCheck(pbReq.Round, pbReq.Epoch, pbReq.Proposer)
	cm.pbs[pbReq.Round][pbReq.Epoch][pbReq.Proposer].ProofReqHandler(cm.proofs[pbReq.Round], pbReq)
}

func (cm *ConsensusModule) HandlePBRes(pbRes message.PBRes) {
	// // cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] handle pbRes from [Endorser:%d].\n",
	// 	pbRes.Round, pbRes.Epoch, cm.id, pbRes.Endorser)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PBCheck(pbRes.Round, pbRes.Epoch, pbRes.Proposer)
	cm.pbs[pbRes.Round][pbRes.Epoch][pbRes.Proposer].ProofResHandler(pbRes)
}

func (cm *ConsensusModule) HandlePBDone(pd message.PBDone) {
	// // cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] handle pbDone from [Leader:%d].\n",
	// 	pd.Round, pd.Epoch, cm.id, pd.Proposer)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.PBCheck(pd.Round, pd.Epoch, pd.Proposer)
	cm.pbs[pd.Round][pd.Epoch][pd.Proposer].ProofDoneHandler(pd)
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
		// cm.logger.Printf("[Round:%d] [Epoch:%d] receive pr out from [%d] proposer.\n", round, epoch, proposer)
		go cm.waitForPB(round, epoch, proposer, pbOut, done)
	} else {
		// cm.logger.Printf("[Round:%d] [Epoch:%d] [Proposer:%d] has been done [RoundEnd!].\n", round, epoch, proposer)
	}
}

func (cm *ConsensusModule) waitForPB(round, epoch, proposer int, pbOut PBOut, done chan PBOut) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.pbs[round][epoch][proposer].Skipped() {
		return
	}

	cm.pbOuts[round][epoch][proposer] = pbOut
	cm.pbs[round][epoch][proposer].Skip()
	close(done)

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

func (cm *ConsensusModule) HandleElect(electReq message.ElectReq) {
	// // cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] handle elect msg from [Endorser:%d].\n",
	// 	electReq.Round, electReq.Epoch, cm.id, electReq.Endorser)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.ElectCheck(electReq.Round, electReq.Epoch)

	leaderId, ok := cm.elects[electReq.Round][electReq.Epoch].ElectReqHandler(electReq)
	if ok {
		// cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] get [Leader:%d].\n", electReq.Round, electReq.Epoch, cm.id, leaderId)
		if _, ok = cm.pbOuts[electReq.Round][1][leaderId]; ok {
			go cm.BAInput(electReq.Round, electReq.Epoch, leaderId, 1)
		} else {
			go cm.BAInput(electReq.Round, electReq.Epoch, leaderId, 0)
		}
	}
}

func (cm *ConsensusModule) BAInput(round, subround, leaderId, est int) {
	// cm.logger.Printf("[Round:%d] [SubRound:%d]: [Peer:%d] input [%d] to BA.\n", round, subround, cm.id, est)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.BACheck(round)
	decide := make(chan int)
	cm.bas[round][subround] = MakeBA(cm.n, cm.f, cm.id, round, subround, est, cm.logger, cm.cs, cm.suite, cm.pubKey, cm.priKey)
	cm.bas[round][subround].decide = decide

	go cm.baMonitor(round, subround, leaderId, decide)

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

func (cm *ConsensusModule) baMonitor(round, subround, leaderId int, decide chan int) {
	value := <-decide
	// cm.logger.Printf("[Round:%d] [SubRound:%d]: [Peer:%d] get [%d] from ba.\n", round, subround, cm.id, value)
	if value == 0 {
		subround++
		go cm.electBroadcast(round, subround)
	} else {
		go cm.roundEnd(round, subround, leaderId)
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

func (cm *ConsensusModule) roundEnd(round, subround, leaderId int) {
	var waitPB chan PBOut
	var proofs map[int]message.Proof

	// If BA output 1, wait for pbout for leaderId.
	cm.mu.Lock()
	if pbOut, ok := cm.pbOuts[round][1][leaderId]; !ok {
		waitPB = cm.pbs[round][1][leaderId].done
	} else {
		proofs = pbOut.proofs
	}
	cm.mu.Unlock()

	if waitPB != nil {
		// cm.logger.Printf("[Round:%d] [SubRound:%d]: [Peer:%d] not receive [%d] pbout.\n",
		// round, subround, cm.id, leaderId)
		if pbOut, ok := <-waitPB; ok {
			proofs = pbOut.proofs
			close(waitPB)
			cm.mu.Lock()
			cm.pbs[round][1][leaderId].Skip()
			cm.pbOuts[round][1][leaderId] = pbOut
			cm.mu.Unlock()
		} else {
			cm.mu.Lock()
			proofs = cm.pbOuts[round][1][leaderId].proofs
			cm.mu.Unlock()
		}
		// cm.logger.Printf("[Round:%d] [SubRound:%d]: [Peer:%d] receive [%d] pbout after wait.\n",
		// round, subround, cm.id, leaderId)
	}

	// cm.logger.Printf("[Round:%d] receive [%d] pbout.\n", round, leaderId)

	prbcOuts := make(map[int][]byte)
	prbcWaits := make(map[int]chan PRBCOut)

	// If receive pbouts for leaderId, wait for prbc out in proofs.
	cm.mu.Lock()
	for proposer := range proofs {
		if prbcOut, ok := cm.prbcOuts[round][proposer]; ok {
			prbcOuts[proposer] = prbcOut.rbcOut
		} else {
			prbcWaits[proposer] = cm.prbcs[round][proposer].done
		}
	}
	cm.mu.Unlock()

	if len(prbcWaits) > 0 {
		for proposer, wait := range prbcWaits {
			// cm.logger.Printf("[Round:%d] [SubRound:%d]: [Peer:%d] not receive [%d] prbcOut.\n",
			// round, subround, cm.id, proposer)
			if prbcOut, ok := <-wait; ok {
				prbcOuts[proposer] = prbcOut.rbcOut
				close(wait)
				cm.mu.Lock()
				cm.prbcs[round][proposer].Skip()
				cm.prbcOuts[round][proposer] = prbcOut
				cm.mu.Unlock()
			} else {
				cm.mu.Lock()
				prbcOuts[proposer] = cm.prbcOuts[round][proposer].rbcOut
				cm.mu.Unlock()
			}
			// cm.logger.Printf("[Round:%d] [SubRound:%d]: [Peer:%d] receive [%d] prbcOut after wait.\n",
			// round, subround, cm.id, proposer)
		}
	}

	// Close all channel to avoid goroutine leak.
	// Close prbc channel. If not receive prbc out, skip prbc and close prbc channel.
	cm.mu.Lock()
	for proposer := 0; proposer < cm.n; proposer++ {
		if _, ok := cm.prbcOuts[round][proposer]; !ok {
			if _, ok := cm.prbcs[round][proposer]; ok {
				cm.prbcs[round][proposer].Skip()
				close(cm.prbcs[round][proposer].done)
				// cm.logger.Printf("[Round:%d] prbc [%d] skip due to round end.\n", round, proposer)
			}
		} else {
			// cm.logger.Printf("[Round:%d] prbc [%d] done.\n", round, proposer)
		}
	}

	// Close pb channel.
	for epoch := 0; epoch < 2; epoch++ {
		for proposer := 0; proposer < cm.n; proposer++ {
			if _, ok := cm.pbOuts[round][epoch][proposer]; !ok {
				if _, ok := cm.pbs[round][epoch][proposer]; ok {
					if !cm.pbs[round][epoch][proposer].skip {
						cm.pbs[round][epoch][proposer].Skip()
						close(cm.pbs[round][epoch][proposer].done)
						// cm.logger.Printf("[Round:%d] [Epoch:%d] pb [%d] skip due to round end.\n", round, epoch, proposer)
					}
				}
			} else {
				// cm.logger.Printf("[Round:%d] [Epoch:%d] pb [%d] done.\n", round, epoch, proposer)
			}
		}
	}
	cm.mu.Unlock()

	var receivers []int
	for receiver := range prbcOuts {
		receivers = append(receivers, receiver)
	}
	// cm.logger.Printf("[Round:%d] receive [%v] prbc outs.\n", round, receivers)

	cm.mu.Lock()
	clientId := cm.reqs[round].ClientId
	reqCount := cm.reqs[round].RequestCount
	cm.mu.Unlock()

	cliRes := message.ClientRes{
		Round:    round,
		Proposer: cm.id,
		ReqCount: reqCount,
	}

	// cm.logger.Printf("[Round:%d] send client response to [Client:%d].\n", round, clientId)
	cm.cs.ClientResponse(cliRes, clientId)
}

func (cm *ConsensusModule) proofCheck(round int) {
	// Check proof status. If round r proof not init, init proof for round r.
	if _, ok := cm.proofs[round]; !ok {
		cm.proofs[round] = make(map[int]message.Proof)
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
	var prbcRecvs []int
	for recv := range proofs {
		prbcRecvs = append(prbcRecvs, recv)
	}
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
	// cm.logger.Printf("[Round:%d] [Epoch:%d]: [Peer:%d] start pb upon receive [%v].\n", round, epoch, cm.id, prbcRecvs)
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
