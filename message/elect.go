package message

type ElectReq struct {
	Endorser  int
	Round     int
	Epoch     int
	ElectHash []byte
	Share     []byte
}
