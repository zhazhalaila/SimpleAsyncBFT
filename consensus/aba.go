package consensus

import (
	"SimpleAsyncBFT/connector"
	"SimpleAsyncBFT/message"
	"crypto/sha256"
	"log"
	"strconv"
	"sync"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

const (
	BinChange = iota
	AuxRecv   = iota
	ConfRecv  = iota
	CoinRecv  = iota
	Zero      = iota
	One       = iota
	Both      = iota
)

type BA struct {
	mu            sync.Mutex                // Prevent data race.
	n             int                       // Total node number.
	f             int                       // Byzantine node number.
	id            int                       // Peer's identify.
	round         int                       // Consensus round.
	est           int                       // Peer's adopt value.
	epoch         int                       // BA epoch.
	logger        *log.Logger               // Log info (global).
	cs            *connector.ConnectService // Broadcast.
	suite         *bn256.Suite              // Suite to crypto.
	pubKey        *share.PubPoly            // Threshold signature public key.
	priKey        *share.PriShare           // Threshold signature private key.
	binVals       map[int][]int             // Binary values.
	estVals       map[int]map[int][]int     // Est value sender cache.
	auxVals       map[int]map[int][]int     // Aux value sender cache.
	confVals      map[int]map[int][]int     // Conf value sender cache.
	estSent       map[int]map[int]bool      // Est values sent status.
	auxSent       map[int]map[int]bool      // Aux values sent status.
	confSent      map[int]bool              // Conf values sent status.
	coin          map[int]map[int][]byte    // Coin sigs.
	signal        chan eventNotify          // Event signal.
	values        map[int]int               // Epoch values.
	decide        chan int                  // BA output value.
	alreadyDecide bool                      // Loop break condition.
}

type eventNotify struct {
	event int // Event type.
	epoch int // BA epoch.
	coin  int // Output from common coin.
}

func MakeBA(n, f, id, round, est int,
	logger *log.Logger,
	cs *connector.ConnectService,
	suite *bn256.Suite,
	pubKey *share.PubPoly,
	priKey *share.PriShare) *BA {
	ba := &BA{
		n:      n,
		f:      f,
		id:     id,
		round:  round,
		logger: logger,
		cs:     cs,
		suite:  suite,
		pubKey: pubKey,
		priKey: priKey,
	}
	ba.est = est
	ba.epoch = 0
	ba.binVals = make(map[int][]int)
	ba.estVals = make(map[int]map[int][]int)
	ba.auxVals = make(map[int]map[int][]int)
	ba.confVals = make(map[int]map[int][]int)
	ba.estSent = make(map[int]map[int]bool)
	ba.auxSent = make(map[int]map[int]bool)
	ba.confSent = make(map[int]bool)
	ba.coin = make(map[int]map[int][]byte)
	ba.signal = make(chan eventNotify)
	ba.decide = make(chan int)
	ba.values = make(map[int]int)
	ba.alreadyDecide = false
	go ba.estBC()
	go ba.eventHandler()
	return ba
}

func (ba *BA) estBC() {
	ba.mu.Lock()
	ba.baCheck(ba.epoch)
	if !ba.estSent[ba.epoch][ba.est] {
		ba.estSent[ba.epoch][ba.est] = true
	}
	ba.mu.Unlock()

	// Generate est message.
	e := message.EST{
		Sender: ba.id,
		Round:  ba.round,
		Epoch:  ba.epoch,
		BinVal: ba.est,
	}
	// Est message encode.
	estMsg := message.MessageEncode(e)
	// Broad est message.
	ba.cs.Broadcast(estMsg)
}

func (ba *BA) eventHandler() {
	// Event handler.
	for v := range ba.signal {
		if v.event == BinChange {
			go ba.auxBC(v.epoch)
		}
		if v.event == AuxRecv {
			go ba.auxCheck(v.epoch)
		}
		if v.event == ConfRecv {
			go ba.confCheck(v.epoch)
		}
		if v.event == CoinRecv {
			ba.logger.Printf("Coin = %d.\n", v.coin)
		}
	}
}

func (ba *BA) auxBC(epoch int) {
	// Generate aux msg.
	aux := message.AUX{
		Sender: ba.id,
		Round:  ba.round,
		Epoch:  epoch,
	}
	ba.mu.Lock()
	aux.Element = ba.binVals[ba.epoch][len(ba.binVals[ba.epoch])-1]
	ba.mu.Unlock()
	// Encode aux msg.
	auxMsg := message.MessageEncode(aux)
	// Broadcast aux msg.
	ba.logger.Printf("[Round:%d] [Epoch:%d] broad [%d] aux values.\n", ba.round, ba.epoch, aux.Element)
	go ba.cs.Broadcast(auxMsg)
}

func (ba *BA) auxCheck(epoch int) {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	// If conf value has sent, return.
	if ba.confSent[epoch] {
		return
	}

	conf := message.CONF{
		Sender: ba.id,
		Round:  ba.round,
		Epoch:  epoch,
	}

	ba.logger.Printf("[Round:%d] [Epoch:%d] bin values = [%v] aux values = [%v].\n",
		ba.round, ba.epoch, ba.binVals[epoch], ba.auxVals[epoch])

	// If receive >= 2f+1 aux msg with 1, broadcast 1.
	if inSlice(1, ba.binVals[epoch]) && len(ba.auxVals[epoch][1]) >= ba.n-ba.f {
		conf.Val = One
		ba.confBroadcast(epoch, conf)
		return
	}
	// If receive >= 2f+1 aux msg with 0, broadcast 0.
	if inSlice(0, ba.binVals[epoch]) && len(ba.auxVals[epoch][0]) >= ba.n-ba.f {
		conf.Val = Zero
		ba.confBroadcast(epoch, conf)
		return
	}
	// If receive >= 2f+1 aux msg with 0 || 1, broadcast (0,1)
	count := 0
	for _, v := range ba.binVals[epoch] {
		count += len(ba.auxVals[epoch][v])
	}

	if count >= ba.n-ba.f {
		conf.Val = Both
		ba.confBroadcast(epoch, conf)
	}
}

func (ba *BA) confBroadcast(epoch int, conf message.CONF) {
	ba.confSent[epoch] = true
	confMsg := message.MessageEncode(conf)
	ba.logger.Printf("[Round:%d] [epoch:%d] broadcast [%t].\n", ba.round, epoch, conf.Val == Both)
	go ba.cs.Broadcast(confMsg)
}

func (ba *BA) confCheck(epoch int) {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	ba.logger.Printf("[Round:%d] [Epoch:%d] bin values = [%v] conf values = [%v].\n",
		ba.round, ba.epoch, ba.binVals[epoch], ba.confVals[epoch])

	if inSlice(1, ba.binVals[epoch]) && len(ba.confVals[epoch][One]) >= ba.n-ba.f {
		ba.logger.Printf("[Round:%d] [Epoch:%d] receive n-f [1] msg", ba.round, epoch)
		ba.coinBC(epoch, One)
		return
	}

	if inSlice(0, ba.binVals[epoch]) && len(ba.confVals[epoch][Zero]) >= ba.n-ba.f {
		ba.logger.Printf("[Round:%d] [Epoch:%d] receive n-f [0] msg", ba.round, epoch)
		ba.coinBC(epoch, Zero)
		return
	}

	count := 0
	for _, v := range ba.binVals[epoch] {
		if v == 0 {
			count += len(ba.confVals[epoch][Zero])
		}
		if v == 1 {
			count += len(ba.confVals[epoch][One])
		}
	}

	if len(ba.binVals[epoch]) == 2 {
		count += len(ba.confVals[epoch][Both])
	}

	ba.logger.Printf("Conf counter = %d.\n", count)
	if count >= ba.n-ba.f {
		ba.logger.Printf("[Round:%d] [Epoch:%d] receive n-f [(0,1)] msg", ba.round, epoch)
		ba.coinBC(epoch, Both)
		return
	}
}

func (ba *BA) coinBC(epoch, val int) {
	if _, ok := ba.values[epoch]; !ok {
		ba.values[epoch] = val
	} else {
		return
	}

	go func() {
		str := strconv.Itoa(ba.round) + "-" + strconv.Itoa(epoch)
		strJs := message.ConvertStructToHashBytes(str)
		hashMsg := sha256.Sum256(strJs)
		share := message.GenShare(hashMsg[:], ba.suite, ba.priKey)

		// Generate coin msg.
		coin := message.COIN{
			Sender:  ba.id,
			Round:   ba.round,
			Epoch:   epoch,
			HashMsg: hashMsg[:],
			Share:   share,
		}
		// Encode coin msg.
		coinMsg := message.MessageEncode(coin)
		// Broadcast coin msg.
		ba.cs.Broadcast(coinMsg)
	}()
}

func (ba *BA) ESTHandler(est message.EST) {
	sender := est.Sender
	epoch := est.Epoch
	v := est.BinVal

	ba.mu.Lock()
	defer ba.mu.Unlock()

	ba.baCheck(epoch)

	if inSlice(sender, ba.estVals[epoch][v]) {
		ba.logger.Printf("[Round:%d][Epoch:%d] receive redundant EST value from [Sender:%d].\n", ba.round, epoch, sender)
		return
	}
	ba.estVals[epoch][v] = append(ba.estVals[epoch][v], sender)

	// Relay after reaching first threshold.
	if len(ba.estVals[epoch][v]) >= ba.f+1 && !ba.estSent[epoch][v] {
		ba.estSent[epoch][v] = true
		go func() {
			// Generate est message.
			e := message.EST{
				Sender: ba.id,
				Round:  ba.round,
				Epoch:  epoch,
				BinVal: v,
			}
			// Est message encode.
			estMsg := message.MessageEncode(e)
			ba.cs.Broadcast(estMsg)
		}()
	}

	// Broadcast aux signal.
	if len(ba.estVals[epoch][v]) >= 2*ba.f+1 {
		if !inSlice(v, ba.binVals[epoch]) {
			ba.binVals[epoch] = append(ba.binVals[epoch], v)
			ba.signal <- eventNotify{event: BinChange, epoch: epoch}
		}
	}
}

func (ba *BA) AUXHandler(aux message.AUX) {
	sender := aux.Sender
	epoch := aux.Epoch
	e := aux.Element

	ba.mu.Lock()
	defer ba.mu.Unlock()

	ba.baCheck(epoch)

	if inSlice(sender, ba.auxVals[epoch][e]) {
		ba.logger.Printf("[Round:%d][Epoch:%d] receive redundant AUX value from [Sender:%d].\n", ba.round, epoch, sender)
		return
	}

	ba.auxVals[epoch][e] = append(ba.auxVals[epoch][e], sender)
	ba.signal <- eventNotify{event: AuxRecv, epoch: epoch}
}

func (ba *BA) ConfHandler(conf message.CONF) {
	sender := conf.Sender
	epoch := conf.Epoch
	val := conf.Val

	ba.mu.Lock()
	defer ba.mu.Unlock()

	ba.baCheck(epoch)

	if inSlice(sender, ba.confVals[epoch][val]) {
		ba.logger.Printf("[Round:%d][Epoch:%d] receive redundant CONF value from [Sender:%d].\n", ba.round, epoch, sender)
		return
	}
	ba.confVals[epoch][val] = append(ba.confVals[epoch][val], sender)
	ba.signal <- eventNotify{event: ConfRecv, epoch: epoch}
}

func (ba *BA) CoinHandler(coin message.COIN) {
	sender := coin.Sender
	epoch := coin.Epoch
	hashMsg := coin.HashMsg
	share := coin.Share

	if !message.ShareVerify(hashMsg, share, ba.suite, ba.pubKey) {
		return
	}

	ba.mu.Lock()
	defer ba.mu.Unlock()

	ba.baCheck(epoch)

	if _, ok := ba.coin[epoch][sender]; !ok {
		ba.coin[epoch][sender] = share
	}

	ba.logger.Printf("[Round:%d] [Epoch:%d] receive [%d] coin msg.\n", ba.round, epoch, len(ba.coin[epoch]))

	if len(ba.coin[epoch]) > ba.f+1 {
		return
	}

	if len(ba.coin[epoch]) == ba.f+1 {
		var shares [][]byte
		for _, share := range ba.coin[epoch] {
			shares = append(shares, share)
		}
		signature := message.ComputeSignature(hashMsg, ba.suite, shares, ba.pubKey, ba.n, ba.f+1)
		if message.SignatureVerify(hashMsg, signature, ba.suite, ba.pubKey) {
			coinHash := sha256.Sum256(signature)
			ba.signal <- eventNotify{event: CoinRecv, epoch: epoch, coin: int(coinHash[0]) % 2}
		}
	}
}

func (ba *BA) baCheck(epoch int) {
	if _, ok := ba.coin[epoch]; !ok {
		ba.coin[epoch] = make(map[int][]byte)
	}
	if _, ok := ba.estSent[epoch]; !ok {
		ba.estSent[epoch] = make(map[int]bool)
	}
	if _, ok := ba.estVals[epoch]; !ok {
		ba.estVals[epoch] = make(map[int][]int)
	}
	if _, ok := ba.confVals[epoch]; !ok {
		ba.confVals[epoch] = make(map[int][]int)
	}
	if _, ok := ba.auxVals[epoch]; !ok {
		ba.auxVals[epoch] = make(map[int][]int)
	}
}

func inSlice(s int, list []int) bool {
	for _, b := range list {
		if b == s {
			return true
		}
	}
	return false
}
