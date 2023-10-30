package main

import (
	"fmt"
	"os"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/urfave/cli/v2"
)

var (
	domainFlag = &cli.StringFlag{
		Name:     "domain",
		Aliases:  []string{"d"},
		Required: true,
		Usage:    "dns domain",
	}
	selectorFlag = &cli.StringFlag{
		Name:    "selector",
		Aliases: []string{"s"},

		Required: true,
		Usage:    "dns selector",
	}
	fileFlag = &cli.StringFlag{
		Name:    "path",
		Aliases: []string{"f"},
		Value:   "./email.eml",
		Usage:   "email path",
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
	ArgsUsage: "<file>",
	Usage:     "extract signature and signed data from email",
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

	N, E := res.Verifier.(dkim.RsaVerifier).GetPublicData()
	if N == nil {
		return fmt.Errorf("parse rsa public key error")
	}
	fmt.Printf("modulus:  %x\n", N.Bytes())
	fmt.Printf("exponent: %08X\n", E)
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
	fmt.Printf("Raw Data: %s\n", string(toSignData))
	return nil
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
