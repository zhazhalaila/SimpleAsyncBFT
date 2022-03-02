package consensus

import (
	"SimpleAsyncBFT/connector"
	"SimpleAsyncBFT/message"
	"bytes"
	"log"
	"sync"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type PBOut struct {
	proofs map[int]message.Proof
}

type PB struct {
	mu         sync.Mutex
	n          int
	f          int
	id         int
	round      int
	epoch      int
	fromLeader int
	logger     *log.Logger
	cs         *connector.ConnectService // Broadcast.
	suite      *bn256.Suite              // Suite to crypto.
	pubKey     *share.PubPoly            // Threshold signature public key.
	priKey     *share.PriShare           // Threshold signature private key.
	shares     map[int][]byte
	proofs     map[int]message.Proof
	signature  []byte
	done       chan PBOut
	skip       bool
}

func MakePB(n, f, id, round, epoch, proposer int,
	logger *log.Logger,
	cs *connector.ConnectService,
	suite *bn256.Suite,
	pubKey *share.PubPoly,
	priKey *share.PriShare,
) *PB {
	pb := &PB{}
	pb.n = n
	pb.f = f
	pb.id = id
	pb.round = round
	pb.epoch = epoch
	pb.fromLeader = proposer
	pb.logger = logger
	pb.cs = cs
	pb.suite = suite
	pb.pubKey = pubKey
	pb.priKey = priKey
	pb.shares = make(map[int][]byte)
	pb.proofs = make(map[int]message.Proof)
	pb.skip = false
	return pb
}

func (pb *PB) ProofReqHandler(recvProof map[int]message.Proof, pr message.PBReq) {
	if pb.skip {
		return
	}

	proofs := pr.Proofs

	// For loop to check.
	// 1. If proof has received but current proof != received proof, return.
	// 2. If proof has not received but current proof is invalid, return.
	for index, proof := range proofs {
		if received, ok := recvProof[index]; ok {
			if !bytes.Equal(proof.Signature, received.Signature) {
				return
			}
		} else if message.SignatureVerify(proof.RootHash, proof.Signature, pb.suite, pb.pubKey) {
			recvProof[index] = proof
		} else {
			return
		}
	}

	/*
	 */

	pb.proofs = proofs
	// Send share for proofHash to proposer.
	// Generate pbres msg.
	pbRes := message.PBRes{
		Proposer:  pr.Proposer,
		Endorser:  pb.id,
		Round:     pb.round,
		Epoch:     pb.epoch,
		ProofHash: pr.ProofHash,
		Share:     message.GenShare(pr.ProofHash, pb.suite, pb.priKey),
	}
	// Encode pbres msg.
	pbResMsg := message.MessageEncode(pbRes)
	// Send share to proposer.
	go pb.cs.SendToPeer(pr.Proposer, pbResMsg)
}

func (pb *PB) ProofResHandler(ps message.PBRes) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	if pb.skip {
		return
	}

	endorser := ps.Endorser
	share := ps.Share

	if _, ok := pb.shares[endorser]; ok {
		pb.logger.Printf("[Round:%d] [Epoch:%d] receive redundant proofRes msg from [%d].\n",
			pb.round, pb.epoch, endorser)
		return
	}

	// Create a goroutine to compute signature to avoid holding lock for a long time.
	go func() {
		if !message.ShareVerify(ps.ProofHash, ps.Share, pb.suite, pb.pubKey) {
			return
		} else {
			pb.mu.Lock()
			pb.shares[endorser] = share
			pb.mu.Unlock()
		}

		pb.mu.Lock()
		if len(pb.shares) == 2*pb.f+1 {
			var shares [][]byte
			for _, share := range pb.shares {
				shares = append(shares, share)
			}
			pb.mu.Unlock()
			signature := message.ComputeSignature(ps.ProofHash, pb.suite, shares, pb.pubKey, pb.n, pb.f+1)
			if message.SignatureVerify(ps.ProofHash, signature, pb.suite, pb.pubKey) {
				pb.mu.Lock()
				pb.signature = signature
				pb.mu.Unlock()
				// Generate pb done msg.
				pbDone := message.PBDone{
					Proposer:  pb.id,
					Round:     pb.round,
					Epoch:     pb.epoch,
					ProofHash: ps.ProofHash,
					Signature: signature,
				}
				// Encode pb done msg.
				pbDoneMsg := message.MessageEncode(pbDone)
				// Broadcast pb done msg except itself.
				go func() {
					for i := 0; i < pb.n; i++ {
						if i != pb.id {
							pb.cs.SendToPeer(i, pbDoneMsg)
						}
					}
				}()
				pb.outToChannel()
			}
		} else {
			pb.mu.Unlock()
		}
	}()
}

func (pb *PB) ProofDoneHandler(pd message.PBDone) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	if pb.skip {
		return
	}

	proposer := pd.Proposer
	proofHash := pd.ProofHash
	signature := pd.Signature

	// Check proofDone send from leader.
	if proposer != pb.fromLeader {
		return
	}

	// If decide, return.
	if pb.signature != nil {
		return
	}

	go func() {
		if message.SignatureVerify(proofHash, signature, pb.suite, pb.pubKey) {
			pb.mu.Lock()
			pb.signature = signature
			pb.mu.Unlock()
			pb.outToChannel()
		}
	}()
}

func (pb *PB) Skip() {
	pb.mu.Lock()
	pb.skip = true
	pb.mu.Unlock()
}

func (pb *PB) outToChannel() {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	pb.logger.Printf("[Round:%d] [Epoch:%d]: [PB:%d] out to channel.\n", pb.round, pb.epoch, pb.fromLeader)

	pb.done <- PBOut{
		proofs: pb.proofs,
	}
}
