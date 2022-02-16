package connector

import (
	"SimpleAsyncBFT/libnet"
	"SimpleAsyncBFT/message"
	"encoding/json"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"
)

type ConnectService struct {
	logger   *log.Logger      // Log info.
	network  *libnet.Network  // Get client connection.
	mu       sync.Mutex       // Lock to prevent race condition.
	peers    map[int]net.Conn // All connection pool.
	clients  map[int]string   // Write response to client.
	delayMin int              // Network delay simulation (lowest bound).
	delayMax int              // Network delay simulation (highest bound).
}

func MakeConnectService(logger *log.Logger, network *libnet.Network) *ConnectService {
	cs := &ConnectService{}
	cs.network = network
	cs.logger = logger
	cs.peers = make(map[int]net.Conn)
	cs.clients = make(map[int]string)
	cs.delayMin = 5
	cs.delayMax = 10
	return cs
}

// Connect to other peer.
func (cs *ConnectService) ConnectOtherPeer(msg message.ConnectPeer) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	peerId := msg.PeerId
	add := msg.Address

	if _, ok := cs.peers[peerId]; ok {
		cs.logger.Printf("[%d] node has been connected.\n", peerId)
	} else {
		conn, err := net.Dial("tcp", add)
		if err != nil {
			cs.logger.Fatal(err)
		}
		cs.logger.Printf("Connect to [Peer:%d].\n", peerId)
		cs.logger.Println(cs.peers)
		cs.peers[peerId] = conn
		cs.logger.Println(cs.peers)
	}
}

// Send message to one peer.
func (cs *ConnectService) SendToPeer(peerId int, msg message.ReqMsg) {
	// Network delay simulation (local server network delay is so low. e.g. under 2 ms)
	delayTime := rand.Intn(cs.delayMax-cs.delayMin) + cs.delayMin
	time.Sleep(time.Duration(delayTime) * time.Millisecond)
	// cs.logger.Printf("Send msg to [%d] peer delay time = [%d].\n", peerId, delayTime)

	cs.mu.Lock()
	peer := cs.peers[peerId]
	cs.mu.Unlock()

	if peer != nil {
		jsMsg, err := json.Marshal(msg)
		if err != nil {
			cs.logger.Println(err)
		} else {
			_, err := peer.Write(jsMsg)
			if err != nil {
				cs.logger.Println(err)
			}
		}
	}
}

// Broadcast message to all peers.
func (cs *ConnectService) Broadcast(msg message.ReqMsg) {
	for peerId := range cs.peers {
		go func(peerId int) {
			cs.SendToPeer(peerId, msg)
		}(peerId)
	}
}
