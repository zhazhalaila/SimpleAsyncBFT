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

// type DisconnectClient struct {
// 	ClientId int
// }

type DelaySimulation struct {
	DeplayMin int
	DeplayMax int
}
