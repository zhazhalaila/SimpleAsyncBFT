package consensus

import (
	"SimpleAsyncBFT/connector"
	"SimpleAsyncBFT/message"
	"crypto/sha256"
	"log"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type Elect struct {
	n         int
	f         int
	id        int
	round     int
	epoch     int
	logger    *log.Logger
	cs        *connector.ConnectService // Broadcast.
	suite     *bn256.Suite              // Suite to crypto.
	pubKey    *share.PubPoly            // Threshold signature public key.
	priKey    *share.PriShare           // Threshold signature private key.
	shares    map[int][]byte            // Received valid elect shares.
	signature []byte                    // Signature combine from shares (at least f+1).
}

func MakeElect(n, f, id, round, epoch int,
	logger *log.Logger,
	cs *connector.ConnectService,
	suite *bn256.Suite,
	pubKey *share.PubPoly,
	priKey *share.PriShare,
) *Elect {
	e := &Elect{}
	e.n = n
	e.f = f
	e.id = id
	e.round = round
	e.epoch = epoch
	e.logger = logger
	e.cs = cs
	e.suite = suite
	e.pubKey = pubKey
	e.priKey = priKey
	e.shares = make(map[int][]byte)
	return e
}

func (e *Elect) ElectReqHandler(er message.ElectReq) (int, bool) {
	endorser := er.Endorser
	electHash := er.ElectHash
	share := er.Share

	if _, ok := e.shares[endorser]; ok {
		e.logger.Printf("[Round:%d] [Epoch:%d] : receive redundant elect msg from [Endorser:%d].\n",
			e.round, e.epoch, endorser)
		return -1, false
	}

	if message.ShareVerify(electHash, share, e.suite, e.pubKey) {
		e.shares[endorser] = share
	} else {
		e.logger.Printf("[Round:%d] [Epoch:%d]: receive invalid share from [Endorser:%d].\n",
			e.round, e.epoch, endorser)
		return -1, false
	}

	if e.signature == nil && len(e.shares) == e.f+1 {
		var endorsers []int
		var shares [][]byte
		for endorser, share := range e.shares {
			shares = append(shares, share)
			endorsers = append(endorsers, endorser)
		}
		e.logger.Printf("[Round:%d] [Epoch:%d] receive f+1 valid share from [%v].\n", e.round, e.epoch, endorsers)

		signature := message.ComputeSignature(electHash, e.suite, shares, e.pubKey, e.n, e.f+1)

		if message.SignatureVerify(electHash, signature, e.suite, e.pubKey) {
			e.signature = signature
			leaderHash := sha256.Sum256(signature)
			return int(leaderHash[0]) % e.n, true
		}
	}

	return -1, false
}
