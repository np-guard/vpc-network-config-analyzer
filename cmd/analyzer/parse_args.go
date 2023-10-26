package main

import (
	"flag"
	"fmt"
	"strings"
)

// InArgs contains the input arguments for the analyzer
type InArgs struct {
	InputConfigFile *string
	OutputFile      *string
	OutputFormat    *string
	AnalysisType    *string
	Grouping        *bool
	VPC             *string
	Debug           *bool
}

const (
	// output formats supported
	JSONFormat       = "json"
	TEXTFormat       = "txt"
	MDFormat         = "md"
	DRAWIOFormat     = "drawio"
	ARCHDRAWIOFormat = "arch_drawio"
	DEBUGFormat      = "debug"

	// connectivity analysis types supported
	allEndpoints = "all_endpoints" // vsi to vsi connectivity analysis
	allSubnets   = "all_subnets"   // subnet to subnet connectivity analysis
	singleSubnet = "single_subnet" // single subnet connectivity analysis
)

var supportedOutputFormats = map[string]bool{
	JSONFormat:       true,
	TEXTFormat:       true,
	MDFormat:         true,
	DRAWIOFormat:     true,
	ARCHDRAWIOFormat: true,
	DEBUGFormat:      true,
}
var supportedAnalysisTypes = map[string]bool{
	allEndpoints: true,
	allSubnets:   true,
	singleSubnet: true,
}

func getSupportedValuesString(supportedValues map[string]bool) string {
	valuesList := make([]string, len(supportedValues))
	i := 0
	for value := range supportedValues {
		valuesList[i] = value
		i += 1
	}
	return strings.Join(valuesList, ",")
}

func ParseInArgs(cmdlineArgs []string) (*InArgs, error) {
	args := InArgs{}
	flagset := flag.NewFlagSet("vpc-network-config-analyzer", flag.ContinueOnError)
	args.InputConfigFile = flagset.String("vpc-config", "", "file path to input config")
	args.OutputFile = flagset.String("output-file", "", "file path to store results")
	args.OutputFormat = flagset.String("format", TEXTFormat, "output format; must be one of "+getSupportedValuesString(supportedOutputFormats))
	args.AnalysisType = flagset.String("analysis-type", allEndpoints,
		"supported analysis types: "+getSupportedValuesString(supportedAnalysisTypes))
	args.Grouping = flagset.Bool("grouping", false, "whether to group together src/dst entries with identical connectivity")
	args.VPC = flagset.String("vpc", "", "CRN of the VPC to analyze")
	args.Debug = flagset.Bool("debug", false, "run in debug mode")

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
		return nil, fmt.Errorf("wrong output format %s; must be one of %s", *args.OutputFormat, getSupportedValuesString(supportedOutputFormats))
	}

	if !supportedAnalysisTypes[*args.AnalysisType] {
		flagset.PrintDefaults()
		return nil, fmt.Errorf("wrong analysis type %s; must be one of: %s", *args.AnalysisType, getSupportedValuesString(supportedAnalysisTypes))
	}

	if *args.AnalysisType != allEndpoints && *args.OutputFormat != TEXTFormat && *args.OutputFormat != JSONFormat {
		return nil, fmt.Errorf("currently only txt/json output format supported with %s analysis type", *args.AnalysisType)
	}

	if *args.AnalysisType == singleSubnet && *args.Grouping {
		return nil, fmt.Errorf("currently singleSubnet analysis type does not support grouping")
	}

	if *args.OutputFormat == JSONFormat && *args.Grouping {
		return nil, fmt.Errorf("json output format is not supported with grouping")
	}
	return &args, nil
}
