package consensus

import (
	"SimpleAsyncBFT/connector"
	"SimpleAsyncBFT/message"
	"log"
	"sync"
)

const (
	BinChange = iota
	AuxRecv   = iota
	ConfRecv  = iota
	Coin      = iota
	Zero      = iota
	One       = iota
	Both      = iota
)

type BA struct {
	mu       sync.Mutex                // Prevent data race.
	n        int                       // Total node number.
	f        int                       // Byzantine node number.
	id       int                       // Peer's identify.
	round    int                       // Consensus round.
	est      int                       // Peer's adopt value.
	epoch    int                       // BA epoch.
	logger   *log.Logger               // Log info (global).
	cs       *connector.ConnectService // Broadcast.
	binVals  map[int][]int             // Binary values.
	estVals  map[int]map[int][]int     // Est value sender cache.
	auxVals  map[int]map[int][]int     // Aux value sender cache.
	confVals map[int]map[int][]int     // Conf value sender cache.
	estSent  map[int]map[int]bool      // Est values sent status.
	auxSent  map[int]map[int]bool      // Aux values sent status.
	confSent map[int]bool              // Conf values sent status.
	signal   chan eventNotify          // Event signal.
}

type eventNotify struct {
	event int
	epoch int
}

func MakeBA(n, f, id, round, est int, logger *log.Logger, cs *connector.ConnectService) *BA {
	ba := &BA{
		n:      n,
		f:      f,
		id:     id,
		round:  round,
		logger: logger,
		cs:     cs,
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
	ba.signal = make(chan eventNotify)
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
			ba.auxBroadcast(v.epoch)
		}
		if v.event == AuxRecv {
			ba.auxCheck(v.epoch)
		}
		if v.event == ConfRecv {
			ba.confCheck(v.epoch)
		}
	}
}

func (ba *BA) auxBroadcast(epoch int) {
	// Generate aux msg.
	aux := message.AUX{
		Sender: ba.id,
		Round:  ba.round,
		Epoch:  epoch,
	}
	aux.Element = ba.binVals[ba.epoch][len(ba.binVals[ba.epoch])-1]
	// Encode aux msg.
	auxMsg := message.MessageEncode(aux)
	// Broadcast aux msg.
	ba.logger.Printf("[Round:%d] [Epoch:%d] broad [%d] aux values.\n", ba.round, ba.epoch, aux.Element)
	ba.cs.Broadcast(auxMsg)
}

func (ba *BA) auxCheck(epoch int) {
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
	ba.logger.Printf("[Round:%d] [Epoch:%d] bin values = [%v] conf values = [%v].\n",
		ba.round, ba.epoch, ba.binVals[epoch], ba.confVals[epoch])

	if inSlice(1, ba.binVals[epoch]) && len(ba.confVals[epoch][One]) >= ba.n-ba.f {
		ba.logger.Printf("[Round:%d] [Epoch:%d] receive n-f [1] msg", ba.round, epoch)
		return
	}

	if inSlice(0, ba.binVals[epoch]) && len(ba.confVals[epoch][Zero]) >= ba.n-ba.f {
		ba.logger.Printf("[Round:%d] [Epoch:%d] receive n-f [0] msg", ba.round, epoch)
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
		return
	}
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

func (ba *BA) baCheck(round int) {
	if _, ok := ba.estSent[round]; !ok {
		ba.estSent[round] = make(map[int]bool)
	}
	if _, ok := ba.estVals[round]; !ok {
		ba.estVals[round] = make(map[int][]int)
	}
	if _, ok := ba.confVals[round]; !ok {
		ba.confVals[round] = make(map[int][]int)
	}
	if _, ok := ba.auxVals[round]; !ok {
		ba.auxVals[round] = make(map[int][]int)
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
