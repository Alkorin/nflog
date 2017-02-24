package main

import (
	"fmt"

	"github.com/Alkorin/nflog"
)

func main() {
	n, _ := nflog.New()
	for m := range n.Messages() {
		fmt.Printf("%+v\n", m)
	}
}
