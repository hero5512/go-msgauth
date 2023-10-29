package main

import (
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/ethereum/go-ethereum/log"
	"github.com/urfave/cli/v2"
)

var (
	domainFlag = &cli.StringFlag{
		Name:     "domain",
		Aliases:  []string{"d"},
		Required: true,
		Usage:    "Path to the Ethereum contract ABI json to bind, - for STDIN",
	}
	selectorFlag = &cli.StringFlag{
		Name:    "selector",
		Aliases: []string{"s"},

		Required: true,
		Usage:    "Path to the Ethereum contract ABI json to bind, - for STDIN",
	}
	fileFlag = &cli.StringFlag{
		Name:    "path",
		Aliases: []string{"f"},
		Value:   "./email.eml",
		Usage:   "Path to the Ethereum contract ABI json to bind, - for STDIN",
	}
)

var app = NewApp()

func NewApp() *cli.App {
	app := cli.NewApp()
	app.Version = "v1.0.0"
	app.Usage = "A command-line tool for email analysis:\n" +
		"1. Extract DKIM Header information and signatures from emails.\n" +
		"2. Retrieve public key information based on domain selectors."

	app.Name = "dkim-inspector"
	app.Flags = []cli.Flag{
		fileFlag,
	}

	app.Commands = []*cli.Command{
		inspectEmailCommand,
		retrieveDnsCommand,
	}
	return app
}

var inspectEmailCommand = &cli.Command{
	Action:    inspectEmailCmd,
	Name:      "inspect",
	Flags:     []cli.Flag{fileFlag},
	ArgsUsage: "<domain> <selector>",
	Usage:     "retrieve public key from dns",
}

var retrieveDnsCommand = &cli.Command{
	Action:    dnsQueryCmd,
	Name:      "retrieve",
	Flags:     []cli.Flag{domainFlag, selectorFlag},
	ArgsUsage: "<domain> <selector>",
	Usage:     "retrieve public key from dns",
}

func dnsQueryCmd(ctx *cli.Context) error {
	domain := ctx.String(domainFlag.Name)
	selector := ctx.String(selectorFlag.Name)

	res, err := dkim.RetriveDnsTxt(domain, selector)
	if err != nil {
		return err
	}

	pub, ok := res.Verifier.Public().(rsa.PublicKey)
	if !ok {
		return fmt.Errorf("parse rsa public key error")
	}
	fmt.Printf("modulus:  %#x\n", pub.N.Bytes())
	fmt.Printf("exponent: %08X\n", pub.E)
	return nil
}

func inspectEmailCmd(ctx *cli.Context) error {
	path := ctx.String(fileFlag.Name)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	sig, toSignData, err := dkim.InspectEmail(f)
	if err != nil {
		return err
	}
	fmt.Printf("Signature: %08X\n", sig)
	fmt.Printf("Hex Data: %08X\n", toSignData)
	fmt.Println("Raw Data: ", string(toSignData))
	return nil
}

func main() {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, log.StreamHandler(os.Stderr, log.TerminalFormat(true))))

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
