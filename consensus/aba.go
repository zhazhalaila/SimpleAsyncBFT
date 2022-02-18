package consensus

import (
	"SimpleAsyncBFT/connector"
	"SimpleAsyncBFT/message"
	"log"
	"sync"
)

type BA struct {
	mu        sync.Mutex                // Prevent data race.
	n         int                       // Total node number.
	f         int                       // Byzantine node number.
	id        int                       // Peer's identify.
	round     int                       // Consensus round.
	est       int                       // Peer's adopt value.
	epoch     int                       // BA epoch.
	logger    *log.Logger               // Log info (global).
	cs        *connector.ConnectService // Broadcast.
	binVals   map[int][]int             // Binary values.
	estVals   map[int]map[int][]int     // Est value cache.
	auxVals   map[int]map[int][]int     // Aux value cache.
	estSent   map[int]map[int]bool      // Est valus sent status.
	binSignal chan int                  // Binvals change signal.
	auxDone   chan []int                // Aux done.
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
	ba.estSent = make(map[int]map[int]bool)
	ba.binSignal = make(chan int, 1)
	ba.auxDone = make(chan []int, 1)
	go ba.run()
	return ba
}

func (ba *BA) run() {
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

	// Wait for n-f aux message.
readChannel:
	for {
		select {
		case bin := <-ba.binSignal:
			ba.logger.Printf("[Round:%d] [Epoch:%d] bin values = [%v].\n", ba.round, ba.epoch, ba.binVals)
			// Generate aux message.
			aux := message.AUX{
				Sender:  ba.id,
				Round:   ba.round,
				Epoch:   ba.epoch,
				Element: bin,
			}
			// Encode aux message.
			auxMsg := message.MessageEncode(aux)
			ba.cs.Broadcast(auxMsg)
		case value := <-ba.auxDone:
			ba.logger.Printf("[Round:%d] [Epoch:%d] receive [%v] values.\n", ba.round, ba.epoch, value)
			break readChannel
		}
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
	if len(ba.estVals[epoch][v]) == 2*ba.f+1 {
		ba.binVals[epoch] = append(ba.binVals[epoch], v)
		ba.binSignal <- v
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

	if inSlice(1, ba.binVals[epoch]) && len(ba.auxVals[epoch][1]) >= ba.n-ba.f {
		ba.auxDone <- []int{1}
		return
	}

	if inSlice(0, ba.binVals[epoch]) && len(ba.auxVals[epoch][0]) >= ba.n-ba.f {
		ba.auxDone <- []int{0}
		return
	}

	count := 0
	for _, v := range ba.binVals[epoch] {
		count += len(ba.auxVals[epoch][v])
	}
	if count >= ba.n-ba.f {
		ba.auxDone <- []int{0, 1}
	}
}

func (ba *BA) baCheck(round int) {
	if _, ok := ba.estSent[round]; !ok {
		ba.estSent[round] = make(map[int]bool)
	}
	if _, ok := ba.estVals[round]; !ok {
		ba.estVals[round] = make(map[int][]int)
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
