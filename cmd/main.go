package main

import (
  "fmt"

  "github.com/Alkorin/nflog"
)

func main() {
  _ = nflog.New(p)
  for{}
}

func p(b []byte) {
  fmt.Printf("%+v\n", b)
}
