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
	cs.delayMin = 50
	cs.delayMax = 100
	return cs
}

func (cs *ConnectService) SetClient(msg message.SetClient) {
	cs.mu.Lock()
	if _, ok := cs.clients[msg.ClientId]; !ok {
		cs.clients[msg.ClientId] = msg.Address
	} else {
		cs.logger.Printf("[%d] client has been connected.\n", msg.ClientId)
	}
	cs.mu.Unlock()
}

func (cs *ConnectService) ClientResponse(msg message.ClientRes, clientId int) {
	var addr string

	cs.mu.Lock()
	if clientAddr, ok := cs.clients[clientId]; ok {
		addr = clientAddr
	} else {
		cs.mu.Unlock()
		cs.logger.Printf("[%d] client has been unconnected.\n", clientId)
		return
	}
	cs.mu.Unlock()

	// Encode clientres msg.
	msgJs, err := json.Marshal(msg)
	if err != nil {
		cs.logger.Println(err)
		return
	}

	// Write clientres msg. If err, delete client.
	clientConn := cs.network.GetConn(addr)
	if clientConn != nil {
		_, err := clientConn.Write(msgJs)
		if err != nil {
			cs.mu.Lock()
			delete(cs.clients, clientId)
			cs.mu.Unlock()
			cs.logger.Printf("Write to closed [%d] client.\n", clientId)
		}
	}
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
	cs.mu.Lock()
	peers := cs.peers
	cs.mu.Unlock()

	for peerId := range peers {
		go func(peerId int) {
			cs.SendToPeer(peerId, msg)
		}(peerId)
	}
}
