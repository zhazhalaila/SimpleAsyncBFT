package message

type ClientRequest struct {
	ClientId     int
	RequestCount int
}

type Input struct {
	Txs       []string
	ClientReq ClientRequest
}

type ReqMsg struct {
	SvcMeth string // Service method. e.g. "Consensus.HandleInput"
	Args    []byte // Encode payload message to bytes by encoding/gob.
}
