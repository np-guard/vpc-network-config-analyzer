package main

import (
	"flag"
	"fmt"
	"strings"
)

type InArgs struct {
	InputConfigFile *string
	OutputFile      *string
	OutputFormat    *string
}

const (
	JSONFormat       = "json"
	TEXTFormat       = "txt"
	MDFormat         = "md"
	DRAWIOFormat     = "drawio"
	ARCHDRAWIOFormat = "archDrawio"
)

var allFormats = []string{
	JSONFormat,
	TEXTFormat,
	MDFormat,
	DRAWIOFormat,
	ARCHDRAWIOFormat,
}

func validFormat(format string) bool {
	for _, f := range allFormats {
		if f == format {
			return true
		}
	}
	return false
}

func ParseInArgs(cmdlineArgs []string) (*InArgs, error) {
	args := InArgs{}
	flagset := flag.NewFlagSet("vpc-network-config-analyzer", flag.ContinueOnError)
	args.InputConfigFile = flagset.String("vpc-config", "", "file path to input config")
	args.OutputFile = flagset.String("outputfile", "", "file path to store results")
	args.OutputFormat = flagset.String("format", TEXTFormat, "output format; must be one of \""+strings.Join(allFormats, "\"/\"")+"\"")
	err := flagset.Parse(cmdlineArgs)
	if err != nil {
		return nil, err
	}

	if args.InputConfigFile == nil || *args.InputConfigFile == "" {
		flagset.PrintDefaults()
		return nil, fmt.Errorf("missing parameter: vpc-config")
	}

	if !validFormat(*args.OutputFormat) {
		flagset.PrintDefaults()
		return nil, fmt.Errorf("wrong output format %s; must be either %s", *args.OutputFormat, strings.Join(allFormats, "/"))
	}

	return &args, nil
}
