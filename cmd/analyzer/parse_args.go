/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"flag"
	"fmt"
	"slices"
	"strings"
)

// InArgs contains the input arguments for the analyzer
type InArgs struct {
	InputConfigFileList   []string
	InputSecondConfigFile string
	OutputFile            string
	OutputFormat          formatSetting
	AnalysisType          *string
	Grouping              bool
	VPC                   string
	Debug                 bool
	Version               *bool
	ESrc                  string
	EDst                  string
	EProtocol             protocolSetting
	ESrcMinPort           int64
	ESrcMaxPort           int64
	EDstMinPort           int64
	EDstMaxPort           int64
	Provider              provider
	RegionList            []string
	ResourceGroup         string
	DumpResources         string
	Quiet                 bool
	Verbose               bool
}

const (
	// flags
	InputConfigFileList   = "vpc-config"
	InputSecondConfigFile = "vpc-config-second"
	OutputFile            = "output-file"
	OutputFormat          = "format"
	AnalysisType          = "analysis-type"
	VPC                   = "vpc"
	Debug                 = "debug"
	ESrc                  = "src"
	EDst                  = "dst"
	EProtocol             = "protocol"
	ESrcMinPort           = "src-min-port"
	ESrcMaxPort           = "src-max-port"
	EDstMinPort           = "dst-min-port"
	EDstMaxPort           = "dst-max-port"
	Provider              = "provider"
	RegionList            = "region"
	ResourceGroup         = "resource-group"
	DumpResources         = "dump-resources"
	Quiet                 = "quiet"
	Verbose               = "verbose"

	// output formats supported
	JSONFormat       = "json"
	TEXTFormat       = "txt"
	MDFormat         = "md"
	DRAWIOFormat     = "drawio"
	ARCHDRAWIOFormat = "arch_drawio"
	SVGFormat        = "svg"
	ARCHSVGFormat    = "arch_svg"
	HTMLFormat       = "html"
	ARCHHTMLFormat   = "arch_html"
	DEBUGFormat      = "debug"

	// connectivity analysis types supported
	allEndpoints     = "all_endpoints"      // vsi to vsi connectivity analysis
	allSubnets       = "all_subnets"        // subnet to subnet connectivity analysis
	singleSubnet     = "single_subnet"      // single subnet connectivity analysis
	allEndpointsDiff = "diff_all_endpoints" // semantic diff of allEndpoints analysis between two configurations
	allSubnetsDiff   = "diff_all_subnets"   // semantic diff of allSubnets analysis between two configurations
	explainMode      = "explain"            // explain specified connectivity, given src,dst and connection

	// separator
	separator = ", "
)

// supportedAnalysisTypesMap is a map from analysis type to its list of supported output formats
var supportedAnalysisTypesMap = map[string][]string{
	allEndpoints: {
		TEXTFormat, MDFormat, JSONFormat, DRAWIOFormat, ARCHDRAWIOFormat,
		SVGFormat, ARCHSVGFormat, HTMLFormat, ARCHHTMLFormat, DEBUGFormat},
	allSubnets: {
		TEXTFormat, MDFormat, JSONFormat, DRAWIOFormat, ARCHDRAWIOFormat,
		SVGFormat, ARCHSVGFormat, HTMLFormat, ARCHHTMLFormat},
	singleSubnet:     {TEXTFormat},
	allEndpointsDiff: {TEXTFormat, MDFormat},
	allSubnetsDiff:   {TEXTFormat, MDFormat},
	explainMode:      {TEXTFormat, DEBUGFormat},
}

// supportedAnalysisTypesList is an ordered list of supported analysis types (usage details presented in this order)
var supportedAnalysisTypesList = []string{
	allEndpoints,
	allSubnets,
	singleSubnet,
	allEndpointsDiff,
	allSubnetsDiff,
	explainMode,
}

func getSupportedAnalysisTypesMapString() string {
	valuesList := make([]string, len(supportedAnalysisTypesList)+1)
	i := 0
	for _, key := range supportedAnalysisTypesList {
		valuesList[i] = "* " + key + "  - supported with: " + strings.Join(supportedAnalysisTypesMap[key], separator)
		i += 1
	}
	return strings.Join(valuesList, "\n")
}

func ParseInArgs(cmdlineArgs []string) (*InArgs, error) {
	args := InArgs{}
	flagset := flag.NewFlagSet("vpc-network-config-analyzer", flag.ContinueOnError)
	//flagset.Var(&args.InputConfigFileList, InputConfigFileList, "Required. File paths to input configs, can pass multiple config files")
	//args.InputSecondConfigFile = flagset.String(InputSecondConfigFile, "", "File path to the 2nd input config; "+
	//	"relevant only for analysis-type diff_all_endpoints and for diff_all_subnets")
	//args.OutputFile = flagset.String(OutputFile, "", "File path to store results")
	// args.OutputFormat = flagset.String(OutputFormat, TEXTFormat,
	//	"Output format; must be one of:\n"+strings.Join(supportedOutputFormatsList, separator))
	args.AnalysisType = flagset.String(AnalysisType, allEndpoints,
		"Supported analysis types:\n"+getSupportedAnalysisTypesMapString())
	//	args.Grouping = flagset.Bool(Grouping, false, "Whether to group together src/dst entries with identical connectivity\n"+
	//		"Does not support single_subnet, diff_all_endpoints and diff_all_subnets analysis-types and json output format")
	//args.VPC = flagset.String(VPC, "", "CRN of the VPC to analyze")
	//args.Debug = flagset.Bool(Debug, false, "Run in debug mode")
	// args.ESrc = flagset.String(ESrc, "", "Source "+srcDstUsage)
	// args.EDst = flagset.String(EDst, "", "Destination "+srcDstUsage)
	// args.EProtocol = flagset.String(EProtocol, "", "Protocol for connection description")
	// args.ESrcMinPort = flagset.Int64(ESrcMinPort, connection.MinPort, "Minimum source port for connection description")
	// args.ESrcMaxPort = flagset.Int64(ESrcMaxPort, connection.MaxPort, "Maximum source port for connection description")
	// args.EDstMinPort = flagset.Int64(EDstMinPort, connection.MinPort, "Minimum destination port for connection description")
	// args.EDstMaxPort = flagset.Int64(EDstMaxPort, connection.MaxPort, "Maximum destination port for connection description")
	//	args.Provider = flagset.String(Provider, "", "Collect resources from an account in this cloud provider")
	//args.ResourceGroup = flagset.String(ResourceGroup, "", "Resource group id or name from which to collect resources")
	//flagset.Var(&args.RegionList, RegionList, "Cloud region from which to collect resources, can pass multiple regions")
	// args.DumpResources = flagset.String(DumpResources, "", "File path to store resources collected from the cloud provider")

	err := flagset.Parse(cmdlineArgs)
	if err != nil {
		return nil, err
	}
	err = errorInArgs(&args, flagset)
	if err != nil {
		return nil, err
	}
	err = notSupportedYetArgs(&args)
	if err != nil {
		return nil, err
	}

	return &args, nil
}

func errorInArgs(args *InArgs, flagset *flag.FlagSet) error {
	if _, ok := supportedAnalysisTypesMap[*args.AnalysisType]; !ok {
		flagset.PrintDefaults()
		return fmt.Errorf("wrong analysis type '%s'; must be one of: '%s'",
			*args.AnalysisType, strings.Join(supportedAnalysisTypesList, separator))
	}
	if !slices.Contains(supportedAnalysisTypesMap[*args.AnalysisType], string(args.OutputFormat)) {
		flagset.PrintDefaults()
		return fmt.Errorf("wrong output format '%s' for analysis type '%s'; must be one of: %s",
			args.OutputFormat, *args.AnalysisType, strings.Join(supportedAnalysisTypesMap[*args.AnalysisType], separator))
	}
	return nil
}

func notSupportedYetArgs(args *InArgs) error {
	diffAnalysis := *args.AnalysisType == allEndpointsDiff || *args.AnalysisType == allSubnetsDiff
	if (*args.AnalysisType == singleSubnet || diffAnalysis) && args.Grouping {
		return fmt.Errorf("currently %s analysis type does not support grouping", *args.AnalysisType)
	}
	if args.OutputFormat == JSONFormat && args.Grouping {
		return fmt.Errorf("json output format is not supported with grouping")
	}
	return nil
}
