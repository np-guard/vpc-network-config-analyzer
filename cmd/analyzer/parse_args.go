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
	JSONFormat   = "json"
	TEXTFormat   = "txt"
	MDFormat     = "md"
	DRAWIOFormat = "drawio"
)

func ParseInArgs(cmdlineArgs []string) (*InArgs, error) {
	args := InArgs{}
	flagset := flag.NewFlagSet("vpc-network-config-analyzer", flag.ContinueOnError)
	args.InputConfigFile = flagset.String("vpc-config", "", "file path to input config")
	args.OutputFile = flagset.String("outputfile", "", "file path to store results")
	args.OutputFormat = flagset.String("format", TEXTFormat, "output format; must be one of \"json\"/\"txt\"/\"md\"\"drawio\"")
	err := flagset.Parse(cmdlineArgs)
	if err != nil {
		return nil, err
	}

	if args.InputConfigFile == nil || *args.InputConfigFile == "" {
		flagset.PrintDefaults()
		return nil, fmt.Errorf("missing parameter: vpc-config")
	}

	if *args.OutputFormat != JSONFormat && *args.OutputFormat != TEXTFormat && *args.OutputFormat != MDFormat && *args.OutputFormat != DRAWIOFormat {
		flagset.PrintDefaults()
		return nil, fmt.Errorf("wrong output format %s; must be either json/txt/md/drawio", *args.OutputFormat)
	}

	return &args, nil
}
