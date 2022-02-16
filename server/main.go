package main

import (
	"SimpleAsyncBFT/connector"
	"SimpleAsyncBFT/consensus"
	"SimpleAsyncBFT/libnet"
	"flag"
	"log"
	"os"
)

func main() {
	path := flag.String("path", "log.txt", "log file path")
	port := flag.String("port", ":8000", "network port number")
	id := flag.Int("id", 0, "assign a unique number to different server")
	n := flag.Int("n", 4, "total node number")
	f := flag.Int("f", 1, "byzantine node number")
	flag.Parse()

	// Create file to store log.
	logPath := "../" + *path
	logFile, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("error opening file : %v", err)
	}

	defer logFile.Close()

	// Config logger.
	logger := log.New(logFile, "logger: ", log.Lshortfile)
	logger.Print("Start server.")

	// Create network.
	rn := libnet.MakeNetwork(*port, logger)

	// Register connect service.
	cs := connector.MakeConnectService(logger, rn)
	csSvc := libnet.MakeService(cs)
	rn.AddService(csSvc)

	// Register consensus service.
	cm := consensus.MakeConsensusModule(*n, *f, *id, logger, cs)
	cmSvc := libnet.MakeService(cm)
	rn.AddService(cmSvc)

	// Start network.
	rn.Start()
}
