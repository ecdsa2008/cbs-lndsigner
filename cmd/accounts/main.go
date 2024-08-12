package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	lndsigner "github.com/Safulet/cbs-lndsigner"
	"github.com/Safulet/cbs-lndsigner/wallet"
)

func main() {
	var seed string
	var network string

	flag.StringVar(&seed, "seed", "", "Input your seed phrase")
	flag.StringVar(&network, "network", "testnet", `The network for which the node was created in the wallet. One of: 'testnet', 'simnet', 'regtest'`)
	flag.Parse()

	if seed == "" || network == "" {
		panic("input seed phrase, pass phrase and network")
	}

	net, err := lndsigner.GetNet("testnet")
	if err != nil {
		panic(err)
	}

	seedBytes, err := hex.DecodeString(seed)
	if err != nil {
		panic(err)
	}
	exportWallet := wallet.NewWallet(seedBytes, net)
	accounts, err := exportWallet.ListAccounts()
	if err != nil {
		panic(err)
	}

	fmt.Print(accounts["acctList"])
}
