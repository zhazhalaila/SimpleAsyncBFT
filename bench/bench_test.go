package bench

import (
	"SimpleAsyncBFT/message"
	"testing"
)

func TestConsensusLocalWith4Nodes(t *testing.T) {
	testConsensus(t, "../localAddress.txt", 4)
}

func testConsensus(t *testing.T, fileName string, n int) {
	c := NewClient()

	// Read ip address from file.
	ipAddr, err := c.ReadAddress(fileName, n)
	if err != nil {
		t.Errorf(err.Error())
	}

	// Client connect consensus module cluster.
	c.ClientConnectPeers(n, ipAddr)
	// Client notify consensus module peers connect.
	c.PeerConnectToPeer(n, ipAddr)

	var txs []string
	for i := 0; i < 10; i++ {
		txs = append(txs, "Hello World.")
	}
	inputBC := message.Input{
		Txs: txs,
	}
	inputMsg := message.MessageEncode(inputBC)
	c.SendMsg(c.nodes[0].Send, inputMsg)
}
