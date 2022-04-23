package bench

import (
	"bytes"
	"strconv"
)

func Fake250BytesTx(clientId, reqCount, peerId int) string {
	var buffer bytes.Buffer
	buffer.WriteString(strconv.Itoa(clientId))
	buffer.WriteString("-")
	buffer.WriteString(strconv.Itoa(reqCount))
	buffer.WriteString("-")
	buffer.WriteString(strconv.Itoa(peerId))
	for i := 0; i < 245; i++ {
		buffer.WriteString(".")
	}
	return buffer.String()
}

func FakeBatchTx(n, clientId, reqCount, peerId int) []string {
	batchTxs := make([]string, 0)
	for i := 0; i < n; i++ {
		batchTxs = append(batchTxs, Fake250BytesTx(clientId, reqCount, peerId))
	}
	return batchTxs
}
