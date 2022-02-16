package bench

import (
	"SimpleAsyncBFT/message"
	"bufio"
	"encoding/json"
	"log"
	"net"
	"os"
)

type node struct {
	Conn    net.Conn      // Network connection.
	Send    *json.Encoder // Encoder message.
	Receive *json.Decoder // Decoder message.
}

type Client struct {
	nodes map[int]*node
}

func NewClient() *Client {
	c := &Client{}
	c.nodes = make(map[int]*node)
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

func (c *Client) ClientConnectPeers(n int, ipAddr []string) {
	for i := 0; i < n; i++ {
		c.clientConnectNode(ipAddr[i], i)
	}
}

func (c *Client) PeerConnectToPeer(n int, ipAddr []string) {
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			peerConn := message.ConnectPeer{
				Address: ipAddr[j],
				PeerId:  j,
			}
			peerMsg := message.MessageEncode(peerConn)
			c.SendMsg(c.nodes[i].Send, peerMsg)
		}
	}
}

func (c *Client) clientConnectNode(address string, serverId int) {
	Conn, err := net.Dial("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	c.nodes[serverId] = &node{
		Conn:    Conn,
		Send:    json.NewEncoder(Conn),
		Receive: json.NewDecoder(Conn),
	}
}

func (c *Client) SendMsg(send *json.Encoder, msg message.ReqMsg) {
	err := send.Encode(msg)
	if err != nil {
		log.Fatal(err)
	}
}
