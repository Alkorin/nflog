package nflog

import (
  "log"
)

func Example() {
  // Create config
	conf := NewConfig()
  // Listen on group 32
	conf.Groups = []uint16{32}

  // Instanciate NFLog
	n, err := New(conf)
	if err != nil {
    panic(err)
	}

  // Listen for messages
	for m := range n.Messages() {
		log.Printf("Received message: %+v", m)
	}
}
