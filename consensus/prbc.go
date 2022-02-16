package consensus

import (
	"SimpleAsyncBFT/connector"
	merkletree "SimpleAsyncBFT/merkleTree"
	"SimpleAsyncBFT/message"
	"log"
	"sync"

	"github.com/klauspost/reedsolomon"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type PRBC struct {
	mu              sync.Mutex                // Prevent data race.
	n               int                       // Peers number.
	f               int                       // Byzantine peers number.
	k               int                       // Erasure code lower bound.
	logger          *log.Logger               // Log info (global).
	cs              *connector.ConnectService // Broadcast.
	suite           *bn256.Suite              // Suite to crypto.
	pubKey          *share.PubPoly            // Threshold signature public key.
	priKey          *share.PriShare           // Threshold signature private key.
	echoThreshold   int                       // Wait for this many ECHO to send READY.
	readyThreshold  int                       // Wait for this many READY to amplify READY.
	outputThreshold int                       // Wait for this many READY to output.
	fromLeader      int                       // Proposer's id.
	shards          map[int][]byte            // Erasure code shards.
	ready           map[int]int               // Ready sender collect.
	readySent       bool                      // Default false.
	shares          map[int][]byte            // Just proposer will have a non-nil shares.
	signature       []byte                    // Combine from endoer's partial share.
	rbcOut          []byte                    // RBC output.
	done            chan PRBCOut              // Channel to check PRBC done.
}

type PRBCOut struct {
	fromLeader int
	rbcOut     []byte
	rbcSig     []byte
}

func MakePRBC(
	n, f, proposer int,
	logger *log.Logger,
	cs *connector.ConnectService,
	suite *bn256.Suite,
	pubKey *share.PubPoly,
	priKey *share.PriShare) *PRBC {
	pr := &PRBC{}
	pr.n = n
	pr.f = f
	pr.logger = logger
	pr.cs = cs
	pr.suite = suite
	pr.pubKey = pubKey
	pr.priKey = priKey
	pr.k = n - 2*f
	pr.echoThreshold = n - f
	pr.readyThreshold = f + 1
	pr.outputThreshold = 2*f + 1
	pr.fromLeader = proposer
	pr.shards = make(map[int][]byte)
	pr.readySent = false
	pr.ready = make(map[int]int)
	pr.shares = make(map[int][]byte)
	pr.done = make(chan PRBCOut)
	return pr
}

func (pr *PRBC) ValHandler(id, round int, valReq message.Val) {
	rootHash := valReq.RootHash
	branch := valReq.Branch
	shard := valReq.Shard

	if merkletree.MerkleTreeVerify(pr.n, shard, rootHash, branch, id) {
		// Generate echo msg.
		echoBC := message.Echo{
			Proposer: valReq.Proposer,
			Sender:   id,
			Round:    round,
			RootHash: rootHash,
			Branch:   branch,
			Shard:    shard}
		// Encode echo msg.
		echoMsg := message.MessageEncode(echoBC)
		// Broadcast reqmsg.
		go func() {
			pr.logger.Printf("[Round:%d] prbc [%d] broadcast echo msg.\n", round, id)
			pr.cs.Broadcast(echoMsg)
		}()
	}
}

func (pr *PRBC) EchoHandler(id, round int, echoReq message.Echo) {
	sender := echoReq.Sender
	rootHash := echoReq.RootHash
	branch := echoReq.Branch
	shard := echoReq.Shard

	pr.mu.Lock()
	defer pr.mu.Unlock()

	// Redundant validation.
	if _, ok := pr.shards[sender]; ok {
		pr.logger.Printf("[Round:%d] PRBC Redundant ECHO.\n", round)
		return
	}

	// Merkle branch validation.
	if merkletree.MerkleTreeVerify(pr.n, shard, rootHash, branch, sender) {
		pr.shards[sender] = shard
	} else {
		pr.logger.Printf("[Round:%d] PRBC receive invalid echo msg from %d.\n", round, sender)
		return
	}

	if len(pr.shards) >= pr.echoThreshold && !pr.readySent {
		pr.readySent = true
		// Generate ready msg.
		readyBC := message.Ready{
			Proposer: echoReq.Proposer,
			Sender:   id,
			Round:    round,
			RootHash: rootHash}
		// Encode ready msg.
		readyMsg := message.MessageEncode(readyBC)
		// Broadcast reqmsg.
		go func() {
			pr.logger.Printf("[Round:%d] prbc [%d] broadcast ready msg.\n", round, id)
			pr.cs.Broadcast(readyMsg)
		}()
	}

	if len(pr.ready) >= pr.outputThreshold && len(pr.shards) >= pr.k && pr.rbcOut == nil {
		pr.rbcOut = pr.decode()
		go func() {
			pr.proofSend(id, round, rootHash)
		}()
	}
}

func (pr *PRBC) ReadyHandler(id, round int, readyReq message.Ready) {
	sender := readyReq.Sender
	rootHash := readyReq.RootHash

	pr.mu.Lock()
	defer pr.mu.Unlock()

	// Redundant validation.
	if _, ok := pr.ready[sender]; ok {
		pr.logger.Printf("[Round:%d] PRBC Redundant READY.\n", round)
		return
	}
	pr.ready[sender] = sender

	// Amplify ready message.
	if len(pr.ready) >= pr.readyThreshold && !pr.readySent {
		pr.readySent = true
		// Generate ready msg.
		readyBC := message.Ready{
			Proposer: readyReq.Proposer,
			Sender:   id,
			Round:    round,
			RootHash: rootHash}
		// Encode ready msg.
		readyMsg := message.MessageEncode(readyBC)
		// Broadcast reqmsg.
		go func() {
			pr.logger.Printf("[Round:%d] prbc [%d] broadcast ready msg.\n", round, id)
			pr.cs.Broadcast(readyMsg)
		}()
	}

	if len(pr.ready) >= pr.outputThreshold && len(pr.shards) >= pr.k && pr.rbcOut == nil {
		pr.rbcOut = pr.decode()
		go func() {
			pr.proofSend(id, round, rootHash)
		}()
	}
}

// Only leader do this.
func (pr *PRBC) ProofHandler(id, round int, proofReq message.RBCProof) {
	endorser := proofReq.Endorser
	share := proofReq.Share
	rootHash := proofReq.RootHash

	pr.mu.Lock()
	defer pr.mu.Unlock()

	// 1. Check peer identify.
	// 2. If receive > 2f+1 valid shares, pass.
	// 3. If receive invalid shares, pass.
	// 4. If receive 2f+1 valid shares, comput signature and broadcast it.
	if id == pr.fromLeader {
		if pr.signature == nil {
			if _, ok := pr.shares[endorser]; ok {
				pr.logger.Printf("[Round:%d] receive Redundant Proof from [Endorser:%d].\n", round, endorser)
			} else {
				if message.ShareVerify(rootHash, share, pr.suite, pr.pubKey) {
					pr.shares[endorser] = share
				} else {
					pr.logger.Printf("[Round:%d] receive invalid Proof from [Endorser:%d].\n", round, endorser)
				}
			}
			if len(pr.shares) == 2*pr.f+1 {
				pr.logger.Printf("[Round:%d] [Leader:%d] receive enough Proof.\n", round, id)
				var shares [][]byte
				for _, share := range pr.shares {
					shares = append(shares, share)
				}
				signature := message.ComputeSignature(rootHash, pr.suite, shares, pr.pubKey, pr.n, pr.f+1)

				if message.SignatureVerify(rootHash, signature, pr.suite, pr.pubKey) {
					pr.signature = signature
					go func() {
						// Generate finish msg.
						fin := message.Finish{
							Proposer:  proofReq.Proposer,
							LeaderId:  id,
							RootHash:  rootHash,
							Signature: pr.signature,
						}
						// Encode finish msg.
						finMsg := message.MessageEncode(fin)
						// Broadcast finish msg except itself.
						pr.logger.Printf("[Round:%d] [Leader:%d] broadcast signature.\n", round, id)
						for i := 0; i < pr.n; i++ {
							if i != id {
								pr.cs.SendToPeer(i, finMsg)
							}
						}
						// Out to channel.
						pr.outToChannel()
					}()
				} else {
					pr.logger.Printf("[Round:%d] combine invalid signature.\n", round)
				}
			}
		}
	}
}

func (pr *PRBC) FinishHandler(id, round int, finReq message.Finish) {
	leader := finReq.LeaderId
	rootHash := finReq.RootHash
	signature := finReq.Signature

	pr.mu.Lock()
	defer pr.mu.Unlock()

	if leader == pr.fromLeader {
		if pr.signature != nil {
			pr.logger.Printf("[Round:%d] receive redundant Finish msg from [Leader:%d].\n", round, leader)
		} else {
			if message.SignatureVerify(rootHash, signature, pr.suite, pr.pubKey) {
				pr.logger.Printf("[Round:%d] receive valid signature from [Leader:%d].\n", round, leader)
				pr.signature = signature
				go func() {
					pr.outToChannel()
				}()
			}
		}
	}
}

func (pr *PRBC) outToChannel() {
	prOut := PRBCOut{
		fromLeader: pr.fromLeader,
		rbcOut:     pr.rbcOut,
		rbcSig:     pr.signature,
	}
	pr.done <- prOut
}

func (pr *PRBC) proofSend(id, round int, rootHash []byte) {
	// Generate rbc proof.
	rbcProof := message.RBCProof{
		Proposer: pr.fromLeader,
		Endorser: id,
		Round:    round,
		RootHash: rootHash,
		Share:    message.GenShare(rootHash, pr.suite, pr.priKey),
	}
	// Encode rbc proof.
	rpMsg := message.MessageEncode(rbcProof)
	// Send rbc proof.
	pr.logger.Printf("[Round:%d] [Peer:%d] send proof to [Leader:%d].\n", round, id, pr.fromLeader)
	pr.cs.SendToPeer(pr.fromLeader, rpMsg)
}

func (pr *PRBC) decode() []byte {
	decShards := make([][]byte, pr.n)
	for i, shard := range pr.shards {
		decShards[i] = shard
	}
	// Erasure code decode shema.
	dec, err := reedsolomon.New(pr.f+1, 2*pr.f)
	pr.checkErr(err)

	err = dec.Reconstruct(decShards)
	pr.checkErr(err)

	// Join shards to single bytes array.
	var decBytes []byte
	for i := 0; i < pr.f; i++ {
		decBytes = append(decBytes, decShards[i]...)
	}

	/*
		Accoding to reedsolomon, If the data size isn't divisible by the number of shards,
		the last shard will contain extra zeros.
		Zeros cann't split by bytes.Split(s, []byte("0")).
	*/
	for _, element := range decShards[pr.f] {
		if element != 0 {
			decBytes = append(decBytes, element)
		} else {
			break
		}
	}

	return decBytes
}

func (pr *PRBC) checkErr(err error) {
	if err != nil {
		pr.logger.Fatal(err)
	}
}
