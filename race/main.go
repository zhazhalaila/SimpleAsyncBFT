package main

import "sync"

type server struct {
	mu    sync.Mutex
	count int
	done  chan bool
}

func main() {
	s := server{}
	s.done = make(chan bool)

	go func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.done <- true
	}()

	<-s.done
}
