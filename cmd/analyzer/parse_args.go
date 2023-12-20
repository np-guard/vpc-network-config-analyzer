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
	Version               *bool
}

// flagHasValue indicates for each input arg if it is expected to have a value in the cli or not
var flagHasValue = map[string]bool{
	InputConfigFile:       true,
	InputSecondConfigFile: true,
	OutputFile:            true,
	OutputFormat:          true,
	AnalysisType:          true,
	Grouping:              false,
	VPC:                   true,
	Debug:                 false,
	Version:               false,
}

const (
	// flags
	InputConfigFile       = "vpc-config"
	InputSecondConfigFile = "vpc-config-second"
	OutputFile            = "output-file"
	OutputFormat          = "format"
	AnalysisType          = "analysis-type"
	Grouping              = "grouping"
	VPC                   = "vpc"
	Debug                 = "debug"
	Version               = "version"

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

var supportedOutputFormats = map[string][]string{
	JSONFormat:       {allEndpoints, allSubnets},
	TEXTFormat:       {allEndpoints, allSubnets, singleSubnet, allEndpointsDiff, allSubnetsDiff},
	MDFormat:         {allEndpoints, allEndpointsDiff, allSubnetsDiff},
	DRAWIOFormat:     {allEndpoints},
	ARCHDRAWIOFormat: {allEndpoints},
	DEBUGFormat:      {allEndpoints},
}
var supportedAnalysisTypes = map[string][]string{
	allEndpoints:     {TEXTFormat, JSONFormat, MDFormat, DRAWIOFormat, ARCHDRAWIOFormat, DEBUGFormat},
	allSubnets:       {TEXTFormat, JSONFormat},
	singleSubnet:     {TEXTFormat},
	allEndpointsDiff: {TEXTFormat, MDFormat},
	allSubnetsDiff:   {TEXTFormat, MDFormat},
}

func getSupportedValuesString(supportedValues map[string][]string) string {
	valuesList := make([]string, len(supportedValues))
	i := 0
	for key := range supportedValues {
		j := 0
		valuesString := make([]string, len(supportedValues[key])+1)
		for _, value := range supportedValues[key] {
			valuesString[j] = value
			j += 1
		}
		valuesString[j] = "\n"
		valuesList[i] = "* " + key + "  - supported with: " + strings.Join(valuesString, ", ")
		i += 1
	}
	return strings.Join(valuesList, "")
}

// parseCmdLine checks if unspported arguments were passed
func parseCmdLine(cmdlineArgs []string) error {
	argIsFlag := true
	for _, arg := range cmdlineArgs {
		if argIsFlag {
			if arg == "-h" || arg == "--h" || arg == "-help" || arg == "--help" {
				continue
			}
			if arg[0] == '-' {
				key := arg[1:]
				if key == "" {
					return fmt.Errorf("bad syntax: %s", arg)
				}
				if arg[1] == '-' {
					key = arg[2:]
				}
				if val, ok := flagHasValue[key]; ok {
					if val {
						argIsFlag = false
					}
				} else {
					return fmt.Errorf("flag not supported: %s", arg)
				}
			} else {
				return fmt.Errorf("bad flag syntax: %s", arg)
			}
		} else {
			argIsFlag = true
		}
	}
	return nil
}

func ParseInArgs(cmdlineArgs []string) (*InArgs, error) {
	args := InArgs{}
	flagset := flag.NewFlagSet("vpc-network-config-analyzer", flag.ContinueOnError)
	args.InputConfigFile = flagset.String(InputConfigFile, "", "Required. File path to input config")
	args.InputSecondConfigFile = flagset.String(InputSecondConfigFile, "", "File path to the 2nd input config; "+
		"relevant only for analysis-type diff_all_endpoints and for diff_all_subnets")
	args.OutputFile = flagset.String(OutputFile, "", "File path to store results")
	args.OutputFormat = flagset.String(OutputFormat, TEXTFormat,
		"Output format; must be one of:\n"+getSupportedValuesString(supportedOutputFormats))
	args.AnalysisType = flagset.String(AnalysisType, allEndpoints,
		"Supported analysis types:\n"+getSupportedValuesString(supportedAnalysisTypes))
	args.Grouping = flagset.Bool(Grouping, false, "Whether to group together src/dst entries with identical connectivity\n"+
		"Does not support single_subnet analysis-type and json output format")
	args.VPC = flagset.String(VPC, "", "CRN of the VPC to analyze")
	args.Debug = flagset.Bool(Debug, false, "Run in debug mode")
	args.Version = flagset.Bool(Version, false, "Prints the release version number")

	// calling parseCmdLine prior to flagset.Parse to ensure that excessive and unsupported arguments are handled
	// for example, flagset.Parse() ignores input args missing the `-`
	err := parseCmdLine(cmdlineArgs)
	if err != nil {
		return nil, err
	}

	err = flagset.Parse(cmdlineArgs)
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
	if !*args.Version && (args.InputConfigFile == nil || *args.InputConfigFile == "") {
		flagset.PrintDefaults()
		return fmt.Errorf("missing parameter: vpc-config")
	}
	if _, ok := supportedAnalysisTypes[*args.AnalysisType]; !ok {
		flagset.PrintDefaults()
		return fmt.Errorf("wrong analysis type %s; must be one of: %s", *args.AnalysisType, getSupportedValuesString(supportedAnalysisTypes))
	}
	if _, ok := supportedOutputFormats[*args.OutputFormat]; !ok {
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
