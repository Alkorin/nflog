package main

import (
	"fmt"

	"github.com/Alkorin/nflog"
)

func main() {
	conf := nflog.NewConfig()
	n, _ := nflog.New(conf)
	for m := range n.Messages() {
		fmt.Printf("%+v\n", m)
	}
}
