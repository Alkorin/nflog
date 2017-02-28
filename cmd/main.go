package main

import (
	"log"

	"github.com/Alkorin/nflog"
	"github.com/davecgh/go-spew/spew"
)

func main() {
	conf := nflog.NewConfig()
	conf.Groups = []uint16{32}
	conf.CopyRange = 64
	conf.Return.Errors = true

	n, err := nflog.New(conf)
	if err != nil {
		log.Fatal(err.Error())
	}

	for {
		select {
		case m := <-n.Messages():
			spew.Dump(m)
		case e := <-n.Errors():
			spew.Dump(e)
		}
	}
}
