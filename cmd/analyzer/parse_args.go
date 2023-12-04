package main

import (
	"flag"
	"fmt"
	"strings"
)

// InArgs contains the input arguments for the analyzer
type InArgs struct {
	InputConfigFile       *string
	InputSecondConfigFile *string
	OutputFile            *string
	OutputFormat          *string
	AnalysisType          *string
	Grouping              *bool
	VPC                   *string
	Debug                 *bool
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
	allEndpoints     = "all_endpoints"      // vsi to vsi connectivity analysis
	allSubnets       = "all_subnets"        // subnet to subnet connectivity analysis
	singleSubnet     = "single_subnet"      // single subnet connectivity analysis
	allEndpointsDiff = "diff_all_endpoints" // semantic diff of allEndpoints analysis between two configurations
	allSubnetsDiff   = "diff_all_subnets"   // semantic diff of allSubnets analysis between two configurations
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
	allEndpoints:     true,
	allSubnets:       true,
	singleSubnet:     true,
	allEndpointsDiff: true,
	allSubnetsDiff:   true,
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
	args.InputSecondConfigFile = flagset.String("vpc-config-second", "", "file path to the 2nd input config; "+
		"relevant only for analysis-type diff_all_endpoints and for diff_all_subnets")
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
	err = errorInErgs(&args, flagset)
	if err != nil {
		return nil, err
	}
	err = notSupportedYetArgs(&args)
	if err != nil {
		return nil, err
	}

	return &args, nil
}

func errorInErgs(args *InArgs, flagset *flag.FlagSet) error {
	if args.InputConfigFile == nil || *args.InputConfigFile == "" {
		flagset.PrintDefaults()
		return fmt.Errorf("missing parameter: vpc-config")
	}
	if !supportedAnalysisTypes[*args.AnalysisType] {
		flagset.PrintDefaults()
		return fmt.Errorf("wrong analysis type %s; must be one of: %s", *args.AnalysisType, getSupportedValuesString(supportedAnalysisTypes))
	}
	if !supportedOutputFormats[*args.OutputFormat] {
		flagset.PrintDefaults()
		return fmt.Errorf("wrong output format %s; must be one of %s", *args.OutputFormat, getSupportedValuesString(supportedOutputFormats))
	}
	if *args.OutputFormat == DEBUGFormat && *args.AnalysisType != allEndpoints {
		return fmt.Errorf("output format %s supported on for %s", DEBUGFormat, allEndpoints)
	}
	diffAnalysis := *args.AnalysisType == allEndpointsDiff || *args.AnalysisType == allSubnetsDiff
	fileForDiffSpecified := args.InputSecondConfigFile != nil && *args.InputSecondConfigFile != ""
	if fileForDiffSpecified && !diffAnalysis {
		return fmt.Errorf("wrong analysis type %s for 2nd file (%v) specified for diff",
			*args.AnalysisType, *args.InputSecondConfigFile)
	}
	if !fileForDiffSpecified && diffAnalysis {
		return fmt.Errorf("missing parameter vpc-config-second for diff analysis %s", *args.AnalysisType)
	}
	return nil
}

func notSupportedYetArgs(args *InArgs) error {
	diffAnalysis := *args.AnalysisType == allEndpointsDiff || *args.AnalysisType == allSubnetsDiff
	if !diffAnalysis && *args.AnalysisType != allEndpoints && *args.OutputFormat != TEXTFormat &&
		*args.OutputFormat != JSONFormat {
		return fmt.Errorf("currently only txt/json output format supported with %s analysis type", *args.AnalysisType)
	}
	if diffAnalysis && *args.OutputFormat != TEXTFormat && *args.OutputFormat != MDFormat {
		return fmt.Errorf("currently only txt/md output format supported with %s analysis type", *args.AnalysisType)
	}
	if *args.AnalysisType == singleSubnet && *args.Grouping {
		return fmt.Errorf("currently singleSubnet analysis type does not support grouping")
	}
	if *args.OutputFormat == JSONFormat && *args.Grouping {
		return fmt.Errorf("json output format is not supported with grouping")
	}
	return nil
}
