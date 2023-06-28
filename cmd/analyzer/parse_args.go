package main

import (
	"flag"
	"fmt"
)

// InArgs contains the input arguments for the analyzer
type InArgs struct {
	InputConfigFile *string
	OutputFile      *string
	OutputFormat    *string
	AnalysisType    *string
}

const (
	// output formats supported
	JSONFormat = "json"
	TEXTFormat = "txt"
	MDFormat   = "md"

	// connectivity analysis types supported
	VsiLevel     = "vsiLevel"    // vsi to vsi connectivity analysis
	SubnetsLevel = "subnetLevel" // subnet to subnet connectivity analysis
	DebugSubnet  = "debugSubnet" // single subnet connectivity analysis
)

var supportedOutputFormats = map[string]bool{
	JSONFormat: true,
	TEXTFormat: true,
	MDFormat:   true,
}
var supportedAnalysisTypes = map[string]bool{
	VsiLevel:     true,
	SubnetsLevel: true,
	DebugSubnet:  true,
}

func ParseInArgs(cmdlineArgs []string) (*InArgs, error) {
	args := InArgs{}
	flagset := flag.NewFlagSet("vpc-network-config-analyzer", flag.ContinueOnError)
	args.InputConfigFile = flagset.String("vpc-config", "", "file path to input config")
	args.OutputFile = flagset.String("output-file", "", "file path to store results")
	args.OutputFormat = flagset.String("format", TEXTFormat, "output format; must be one of \"json\"/\"txt\"/\"md\"")
	args.AnalysisType = flagset.String("analysis-type", VsiLevel, "supported analysis types: vsiLevel / subnetLevel / debugSubnet")

	err := flagset.Parse(cmdlineArgs)
	if err != nil {
		return nil, err
	}

	if args.InputConfigFile == nil || *args.InputConfigFile == "" {
		flagset.PrintDefaults()
		return nil, fmt.Errorf("missing parameter: vpc-config")
	}

	if !supportedOutputFormats[*args.OutputFormat] {
		flagset.PrintDefaults()
		return nil, fmt.Errorf("wrong output format %s; must be either json/txt/md", *args.OutputFormat)
	}

	if !supportedAnalysisTypes[*args.AnalysisType] {
		flagset.PrintDefaults()
		return nil, fmt.Errorf("wrong analysis type %s; must be either vsiLevel / subnetLevel / debugSubnet", *args.AnalysisType)
	}

	if *args.AnalysisType != VsiLevel && *args.OutputFormat != TEXTFormat {
		return nil, fmt.Errorf("currently only txt output format supported with %s analysis type", *args.AnalysisType)
	}

	return &args, nil
}
