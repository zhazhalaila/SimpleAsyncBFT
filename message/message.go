package message

type Proof struct {
	Sender int
	Proof  string
}

type ReqMsg struct {
	SvcMeth string // Service method. e.g. "Consensus.HandleInput"
	Args    []byte // Encode payload message to bytes by encoding/gob.
}
