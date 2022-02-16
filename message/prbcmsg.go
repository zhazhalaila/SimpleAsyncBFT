package message

type Val struct {
	Proposer int      // Proposer's id.
	Round    int      // Proposer's round.
	RootHash []byte   // Merkle tree root hash.
	Branch   [][]byte // Merkle tree branch for shard.
	Shard    []byte   // Erasure code shard data.
}

type Echo struct {
	Proposer int
	Sender   int
	Round    int
	RootHash []byte
	Branch   [][]byte
	Shard    []byte
}

type Ready struct {
	Proposer int
	Sender   int
	Round    int
	RootHash []byte
}

type RBCProof struct {
	Proposer int
	Endorser int
	Round    int
	RootHash []byte
	Share    []byte // Partial share.
}

type Finish struct {
	Proposer  int
	LeaderId  int // Proposer's id.
	Round     int
	Signature []byte // Signature.
	RootHash  []byte
}
