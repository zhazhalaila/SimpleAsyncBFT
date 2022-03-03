package bench

import (
	"log"
	"testing"
	"time"
)

func TestConsensusLocalWith4Nodes(t *testing.T) {
	testConsensus(t, "../localAddress.txt", 4, 1, -1, 20, 50)
}

func TestConsensusRemoteWith4Nodes(t *testing.T) {
	testConsensus(t, "../remoteAddress.txt", 4, 1, -1, 20, 50)
}

func TestConsensusLocalWith8Nodes(t *testing.T) {
	testConsensus(t, "../localAddress.txt", 8, 2, -1, 10, 20)
}

func TestConsensusLocalWith32Nodes(t *testing.T) {
	testConsensus(t, "../localAddress.txt", 32, 10, -1, 10, 20)
}

func TestConsensusLocalWith1ByzantineNodes(t *testing.T) {
	testConsensus(t, "../localAddress.txt", 4, 1, 0, 10, 20)
}

func testConsensus(t *testing.T, fileName string, n, f, byzantine int, delayMin, delayMax int) {
	c := NewClient(n, f)

	// Read ip address from file.
	ipAddr, err := c.ReadAddress(fileName, n)
	if err != nil {
		t.Errorf(err.Error())
	}

	// Client connect consensus module cluster.
	c.ClientConnectPeers(n, 0, ipAddr)

	// Delay config.
	c.DelayConfig(delayMin, delayMax)

	// Client notify consensus module peers connect.
	c.PeerConnectToPeer(n, byzantine, ipAddr)

	// Client send requests.
	for i := 0; i < 10; i++ {
		req := &request{}
		req.done = make(chan bool)
		c.ClientSendRequest(i, byzantine, req)
		<-req.done
		req.endTime = time.Since(req.startTime)
		log.Println(req.endTime)
	}

	// Remove connection from connector.
	c.ClientClose(0)

	// Compute Latency.
	c.ComputeLatency()
}
