package message

type EST struct {
	Sender   int // Current sender.
	Round    int // Consensus round.
	SubRound int // Number of times BA was run.
	Epoch    int // BA epoch.
	BinVal   int // Binary value.
}

type AUX struct {
	Sender   int
	Round    int
	SubRound int
	Epoch    int
	Element  int // Binary value.
}

type CONF struct {
	Sender   int
	Round    int
	SubRound int
	Epoch    int
	Val      int // Val after receive n-f aux.
}

type COIN struct {
	Sender   int
	Round    int
	SubRound int
	Epoch    int
	HashMsg  []byte // Hash("Round+Epoch")
	Share    []byte // Share(HashMsg)
}
