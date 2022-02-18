package message

type BAInput struct {
	EST int
}

type EST struct {
	Sender int // Current sender.
	Round  int // Consensus round.
	Epoch  int // BA epoch.
	BinVal int // Binary value.
}

type AUX struct {
	Sender  int
	Round   int
	Epoch   int
	Element int // Binary value.
}
