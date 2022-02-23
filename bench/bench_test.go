package bench

import (
	"SimpleAsyncBFT/message"
	"testing"
	"time"
)

func TestConsensusLocalWith4Nodes(t *testing.T) {
	testConsensus(t, "../localAddress.txt", 4)
}

func TestBAWith4Nodes(t *testing.T) {
	testBA(t, "../localAddress.txt", 4, []int{1, 0, 1, 0})
}

func testBA(t *testing.T, fileName string, n int, ests []int) {
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

	time.Sleep(2 * time.Second)

	// BA Input.
	for i := 0; i < n; i++ {
		baInput := message.BAInput{
			EST: ests[i],
		}
		baInputMsg := message.MessageEncode(baInput)
		c.SendMsg(c.nodes[i].Send, baInputMsg)
		time.Sleep(10 * time.Millisecond)
	}
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