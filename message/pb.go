package message

type Proof struct {
	RootHash  []byte
	Signature []byte
}

type PBReq struct {
	Proposer  int           // Proposer's id.
	Round     int           // Consensus module round.
	Epoch     int           // Run pb twice.
	Proofs    map[int]Proof // At least n-f valid prbc out.
	ProofHash []byte        // Proofs hash.
}

type PBRes struct {
	Endorser  int    // Endorser's id.
	Round     int    // Consensus module round.
	Epoch     int    // Run pb twice.
	ProofHash []byte // Proofs hash.
	Share     []byte // Endorser's share generate by proofhash.
}

type PBDone struct {
	Proposer  int
	Round     int
	Epoch     int
	ProofHash []byte
	Signature []byte // Proposer's signature combine from shares.
}
