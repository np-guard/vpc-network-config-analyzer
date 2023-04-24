package main

import (
	"flag"
	"fmt"
)

type InArgs struct {
	InputConfigFile *string
	OutputFile      *string
	OutputFormat    *string
}

const (
	JSONFormat = "json"
	TEXTFormat = "txt"
	MDFormat   = "md"
)

func ParseInArgs(cmdlineArgs []string) (*InArgs, error) {
	args := InArgs{}
	flagset := flag.NewFlagSet("vpc-network-config-analyzer", flag.ContinueOnError)
	args.InputConfigFile = flagset.String("vpc-config", "", "file path to input config")
	args.OutputFile = flagset.String("outputfile", "", "file path to store results")
	args.OutputFormat = flagset.String("format", TEXTFormat, "output format; must be one of \"json\"/\"txt\"/\"md\"")
	err := flagset.Parse(cmdlineArgs)
	if err != nil {
		return nil, err
	}

	if args.InputConfigFile == nil || *args.InputConfigFile == "" {
		flagset.PrintDefaults()
		return nil, fmt.Errorf("missing parameter: InputConfigFile")
	}

	if *args.OutputFormat != JSONFormat && *args.OutputFormat != TEXTFormat && *args.OutputFormat != MDFormat {
		flagset.PrintDefaults()
		return nil, fmt.Errorf("wrong output format %s; must be either json/txt/md", *args.OutputFormat)
	}

	return &args, nil
}
