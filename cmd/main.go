package main

import (
	"fmt"
	"log"

	"github.com/Alkorin/nflog"
)

func main() {
	conf := nflog.NewConfig()
	conf.Groups = []uint16{32}

	n, err := nflog.New(conf)
	if err != nil {
		log.Fatal(err.Error())
	}

	for m := range n.Messages() {
		fmt.Printf("%+v\n", m)
	}
}
