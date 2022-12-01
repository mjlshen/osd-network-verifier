package main

import (
	"flag"
	"os"
)

func main() {
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	clusterId := f.String("cluster-id", "", "OCM internal or external cluster id")
	if err := f.Parse(os.Args[1:]); err != nil {
		panic(err)
	}

	if *clusterId == "" {
		panic("cluster id must not be empty")
	}
}
