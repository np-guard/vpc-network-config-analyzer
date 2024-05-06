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
	AnalysisType          string
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
	err := errorInArgs(&args, flagset)
	if err != nil {
		return nil, err
	}

	return &args, nil
}

func errorInArgs(args *InArgs, flagset *flag.FlagSet) error {
	if !slices.Contains(supportedAnalysisTypesMap[args.AnalysisType], string(args.OutputFormat)) {
		flagset.PrintDefaults()
		return fmt.Errorf("wrong output format '%s' for analysis type '%s'; must be one of: %s",
			args.OutputFormat, args.AnalysisType, strings.Join(supportedAnalysisTypesMap[args.AnalysisType], separator))
	}
	return nil
}
