// Package main contains a CLI for interacting with public metadata from the command line.
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"google3/base/go/flag"
	"google3/base/go/google"
	"google3/base/go/log"
	"google3/privacy/net/common/cpp/public_metadata/go/binarymetadata"
	"google3/third_party/golang/subcommands/subcommands"
)

type parse struct{}

// Execute implements subcommands.Command interface.
func (p *parse) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		fmt.Printf("Expected one argument, got %v\n", f.NArg())
		return subcommands.ExitUsageError
	}
	b, err := base64.StdEncoding.DecodeString(f.Arg(0))
	if err != nil {
		fmt.Printf("Decode failed %v\n", err)
		return subcommands.ExitUsageError
	}
	s, err := binarymetadata.Deserialize(b)
	if err != nil {
		fmt.Printf("Deserialize failed %v\n", err)
		log.ErrorContextf(ctx, "Failed to deserialize metadata: %v", err)
		return subcommands.ExitFailure
	}
	defer s.Free()
	println("Deserialized successfully")
	println(s.String())
	return subcommands.ExitSuccess
}

// Name implements subcommands.Command interface.
func (p *parse) Name() string {
	return "parse"
}

// SetFlags implements subcommands.Command interface.
func (p *parse) SetFlags(flags *flag.FlagSet) {}

// Usage implements subcommands.Command interface.
func (p *parse) Usage() string {
	return `parse <base64 of metadata>
Example: parse AD8AAQAQAAAAAAAAA4QAAAAAZWTjrAACABgAFlVTLFVTLU5ZLE5FVyBZT1JLIENJVFnwAQABAfACAAEA8AMAAQA=
`
}

// Synopsis implements subcommands.Command interface.
func (p *parse) Synopsis() string {
	return "Parses a public metadata file and prints the fields to stdout."
}

func init() {
	subcommands.Register(&parse{}, "")
}

func main() {
	google.Init()
	os.Exit(int(subcommands.Execute(context.Background())))
}
