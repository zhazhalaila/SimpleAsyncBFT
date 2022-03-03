package message

type ConnectPeer struct {
	Address string
	PeerId  int
}

type DisconnectPeer struct {
	PeerId int
}

type SetClient struct {
	Address  string
	ClientId int
}

type ClientRes struct {
	Round    int    // Consensus module round.
	Proposer int    // Who has completed consensus for client request.
	ReqCount int    // Client request count.
	Results  []byte // Consensus results.
}

type DisconnectClient struct {
	ClientId int
}

type DelaySimulation struct {
	DeplayMin int
	DeplayMax int
}
