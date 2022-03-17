package main

import (
	"SimpleAsyncBFT/connector"
	"SimpleAsyncBFT/consensus"
	"SimpleAsyncBFT/libnet"
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"
)

func main() {
	path := flag.String("path", "log.txt", "log file path")
	port := flag.String("port", ":8000", "network port number")
	id := flag.Int("id", 0, "assign a unique number to different server")
	n := flag.Int("n", 4, "total node number")
	f := flag.Int("f", 1, "byzantine node number")
	flag.Parse()

	fmt.Println(*port)
	// Create file to store log.
	logPath := "../" + *path
	logFile, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("error opening file : %v", err)
	}

	defer func() {
		syscall.Dup2(int(logFile.Fd()), int(os.Stderr.Fd()))
		logFile.Close()
	}()

	defer logFile.Close()

	// Config logger.
	logger := log.New(logFile, "logger: ", log.Ldate|log.Ltime|log.Lshortfile)
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
