// Package main contains a CLI for interacting with public metadata from the command line.
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"time"

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
	b, err := base64.RawURLEncoding.DecodeString(f.Arg(0))
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

type validate struct {
	time int64
}

// Execute implements subcommands.Command interface.
func (p *validate) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() < 1 {
		fmt.Printf("Expected at least one argument, got %v\n", f.NArg())
		f.Usage()
		return subcommands.ExitUsageError
	}
	b, err := base64.RawURLEncoding.DecodeString(f.Arg(0))
	if err != nil {
		fmt.Printf("Decode failed %v\n", err)
		return subcommands.ExitUsageError
	}
	t := time.Unix(p.time, 0)
	fmt.Printf("Checking using time %s\n", t.Format(time.RFC3339))
	err = binarymetadata.ValidateMetadataCardinality(b, t)
	if err != nil {
		fmt.Printf("Validate failed %v\n", err)
		return subcommands.ExitFailure
	}
	fmt.Println("Validated successfully")
	return subcommands.ExitSuccess
}

// Name implements subcommands.Command interface.
func (p *validate) Name() string {
	return "validate"
}

// SetFlags implements subcommands.Command interface.
func (p *validate) SetFlags(flags *flag.FlagSet) {
	flags.Int64Var(&p.time, "time", time.Now().Unix(), "Set a time in epoch seconds to validate the extensions against. Defaults to now")
}

// Usage implements subcommands.Command interface.
func (p *validate) Usage() string {
	return `validate <base64 of metadata>
Example: validate AD8AAQAQAAAAAAAAA4QAAAAAZWTjrAACABgAFlVTLFVTLU5ZLE5FVyBZT1JLIENJVFnwAQABAfACAAEA8AMAAQA=

Warning: this does not check the order of extensions.
`
}

// Synopsis implements subcommands.Command interface.
func (p *validate) Synopsis() string {
	return "Checks extensions using cardinality rules."
}

func init() {
	subcommands.Register(&parse{}, "")
	subcommands.Register(&validate{}, "")
}

func main() {
	google.Init()
	os.Exit(int(subcommands.Execute(context.Background())))
}
