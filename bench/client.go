package bench

import (
	"SimpleAsyncBFT/message"
	"bufio"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

type node struct {
	Conn    net.Conn      // Network connection.
	Send    *json.Encoder // Encoder message.
	Receive *json.Decoder // Decoder message.
}

type request struct {
	startTime time.Time
	endTime   time.Duration
	replys    []int
	done      chan bool
}

type Client struct {
	mu       sync.Mutex
	n        int
	f        int
	nodes    map[int]*node
	requests map[int]*request
}

func NewClient(n, f int) *Client {
	c := &Client{}
	c.n = n
	c.f = f
	c.nodes = make(map[int]*node)
	c.requests = make(map[int]*request)
	return c
}

func (c *Client) ReadAddress(path string, n int) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		n--
		if n < 0 {
			break
		}
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

func (c *Client) ClientConnectPeers(n, clientId int, ipAddr []string) {
	for i := 0; i < n; i++ {
		c.clientConnectNode(ipAddr[i], i, clientId)
	}

	c.receiveMonitor(clientId)
}

func (c *Client) receiveMonitor(clientId int) {
	for i := 0; i < c.n; i++ {
		go func(i int) {
			defer func() {
				c.mu.Lock()
				delete(c.nodes, i)
				log.Printf("[Peer:%d] close connection.\n", i)
				c.mu.Unlock()
			}()

			for {
				var msg message.ClientRes
				if err := c.nodes[i].Receive.Decode(&msg); err == io.EOF {
					break
				} else if err != nil {
					log.Println(err)
					break
				}
				log.Printf("[Round:%d] [ClientId:%d] [RequestCount:%d] receive [Proposer:%d] reponse.\n",
					msg.Round, clientId, msg.ReqCount, msg.Proposer)
				go c.responseCount(msg.ReqCount, msg.Proposer)
			}
		}(i)
	}
}

func (c *Client) responseCount(reqCount, proposer int) {
	c.mu.Lock()
	c.requests[reqCount].replys = append(c.requests[reqCount].replys, proposer)
	if len(c.requests[reqCount].replys) == c.f+1 {
		c.mu.Unlock()
		c.requests[reqCount].done <- true
	} else {
		c.mu.Unlock()
	}
}

func (c *Client) ClientSendRequest(reqCount, byzantine int, req *request) {
	c.mu.Lock()
	c.requests[reqCount] = req
	c.requests[reqCount].startTime = time.Now()
	c.mu.Unlock()

	for i := 0; i < c.n; i++ {
		if i == byzantine {
			continue
		}
		txs := FakeBatchTx(65536, 0, 0, i)
		inputBC := message.Input{
			Txs: txs,
			ClientReq: message.ClientRequest{
				ClientId:     0,
				RequestCount: reqCount,
			},
		}
		inputMsg := message.MessageEncode(inputBC)
		c.SendMsg(c.nodes[i].Send, inputMsg)
	}
}

func (c *Client) ClientClose(clientId int) {
	for i := 0; i < c.n; i++ {
		dc := message.DisconnectClient{
			ClientId: clientId,
		}
		dcMsg := message.MessageEncode(dc)
		c.SendMsg(c.nodes[i].Send, dcMsg)
	}
}

func (c *Client) PeerConnectToPeer(n, f int, ipAddr []string) {
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if j == f {
				continue
			}
			peerConn := message.ConnectPeer{
				Address: ipAddr[j],
				PeerId:  j,
			}
			peerMsg := message.MessageEncode(peerConn)
			c.SendMsg(c.nodes[i].Send, peerMsg)
		}
	}
}

func (c *Client) DelayConfig(min, max int) {
	for i := 0; i < c.n; i++ {
		delay := message.DelaySimulation{
			DeplayMin: min,
			DeplayMax: max,
		}
		delayMsg := message.MessageEncode(delay)
		c.SendMsg(c.nodes[i].Send, delayMsg)
	}
}

func (c *Client) ComputeLatency() {
	requestCount := 0
	var totalTime int64
	for _, request := range c.requests {
		requestCount++
		totalTime += request.endTime.Milliseconds()
	}

	log.Printf("BFT protocol consensus [%d] times within [%d] milliseconds.\n", requestCount, totalTime)
	log.Printf("BFT protocol need [%d]milliseconds to consens for a request which [n=%d, f=%d].\n",
		totalTime/int64(requestCount), c.n, c.f)
}

func (c *Client) clientConnectNode(address string, serverId, clientId int) {
	Conn, err := net.Dial("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	c.nodes[serverId] = &node{
		Conn:    Conn,
		Send:    json.NewEncoder(Conn),
		Receive: json.NewDecoder(Conn),
	}

	// Generate set client msg.
	sc := message.SetClient{
		Address:  Conn.LocalAddr().String(),
		ClientId: clientId,
	}
	// Encode set client msg.
	scMsg := message.MessageEncode(sc)
	// Send set client msg.
	c.SendMsg(c.nodes[serverId].Send, scMsg)
}

func (c *Client) SendMsg(send *json.Encoder, msg message.ReqMsg) {
	err := send.Encode(msg)
	if err != nil {
		log.Fatal(err)
	}
}
