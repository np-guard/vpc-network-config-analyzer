package main

import (
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
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
	QProtocol             *string
	QSrcMinPort           *int64
	QSrcMaxPort           *int64
	QDstMinPort           *int64
	QDstMaxPort           *int64
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
	QProtocol:             true,
	QSrcMinPort:           true,
	QSrcMaxPort:           true,
	QDstMinPort:           true,
	QDstMaxPort:           true,
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
	QProtocol             = "q-protocol"
	QSrcMinPort           = "q-src-min-port"
	QSrcMaxPort           = "q-src-max-port"
	QDstMinPort           = "q-dst-min-port"
	QDstMaxPort           = "q-dst-max-port"

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
	explainMode      = "explain"            // explain specified connectivity, given src,dst and connection

	// separator
	separator = ", "
)

var supportedOutputFormatsMap = map[string]bool{
	JSONFormat:       true,
	TEXTFormat:       true,
	MDFormat:         true,
	DRAWIOFormat:     true,
	ARCHDRAWIOFormat: true,
	DEBUGFormat:      true,
}

// supportedAnalysisTypesMap is a map from analysis type to its list of supported output formats
var supportedAnalysisTypesMap = map[string][]string{
	allEndpoints:     {TEXTFormat, MDFormat, JSONFormat, DRAWIOFormat, ARCHDRAWIOFormat, DEBUGFormat},
	allSubnets:       {TEXTFormat, MDFormat, JSONFormat, DRAWIOFormat, ARCHDRAWIOFormat},
	singleSubnet:     {TEXTFormat},
	allEndpointsDiff: {TEXTFormat, MDFormat},
	allSubnetsDiff:   {TEXTFormat, MDFormat},
	explainMode:      {TEXTFormat},
}

// supportedOutputFormatsList is an ordered list of supported output formats (usage details presented in this order)
var supportedOutputFormatsList = []string{
	TEXTFormat,
	MDFormat,
	JSONFormat,
	DRAWIOFormat,
	ARCHDRAWIOFormat,
	DEBUGFormat,
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

// parseCmdLine checks if unsupported arguments were passed
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
		"Output format; must be one of:\n"+strings.Join(supportedOutputFormatsList, separator))
	args.AnalysisType = flagset.String(AnalysisType, allEndpoints,
		"Supported analysis types:\n"+getSupportedAnalysisTypesMapString())
	args.Grouping = flagset.Bool(Grouping, false, "Whether to group together src/dst entries with identical connectivity\n"+
		"Does not support single_subnet, diff_all_endpoints and diff_all_subnets analysis-types and json output format")
	args.VPC = flagset.String(VPC, "", "CRN of the VPC to analyze")
	args.Debug = flagset.Bool(Debug, false, "Run in debug mode")
	args.Version = flagset.Bool(Version, false, "Prints the release version number")
	args.QProtocol = flagset.String(QProtocol, "", "Protocol for connection description")
	args.QSrcMinPort = flagset.Int64(QSrcMinPort, common.MinPort, "SrcMinPort for connection description")
	args.QSrcMaxPort = flagset.Int64(QSrcMaxPort, common.MaxPort, "SrcMaxPort for connection description")
	args.QDstMinPort = flagset.Int64(QDstMinPort, common.MinPort, "DstMinPort for connection description")
	args.QDstMaxPort = flagset.Int64(QDstMaxPort, common.MaxPort, "DstMaxPort for connection description")

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
	err = invalidArgsExplainMode(&args, flagset)
	if err != nil {
		return nil, err
	}

	return &args, nil
}

func wasFlagSpecified(name string, flagset *flag.FlagSet) bool {
	found := false
	flagset.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func wereExplainParamsSpecified(flagset *flag.FlagSet) bool {
	if wasFlagSpecified(QProtocol, flagset) || wasFlagSpecified(QSrcMinPort, flagset) || wasFlagSpecified(QSrcMaxPort, flagset) ||
		wasFlagSpecified(QDstMinPort, flagset) || wasFlagSpecified(QDstMaxPort, flagset) {
		return true
	}

	return false
}

func PortInRange(port int64) bool {
	if port > common.MaxPort || port < common.MinPort {
		return false
	}

	return true
}

func validRangeConnectionExplainMode(args *InArgs) error {
	if *args.QSrcMinPort > *args.QSrcMaxPort {
		return fmt.Errorf("srcMaxPort %d should be higher than srcMinPort %d", *args.QSrcMaxPort, *args.QSrcMinPort)
	}

	if *args.QDstMinPort > *args.QDstMaxPort {
		return fmt.Errorf("DstMaxPort %d should be higher than DstMinPort %d", *args.QSrcMaxPort, *args.QSrcMinPort)
	}

	if !PortInRange(*args.QSrcMinPort) || !PortInRange(*args.QSrcMaxPort) ||
		!PortInRange(*args.QDstMinPort) || !PortInRange(*args.QDstMaxPort) {
		return fmt.Errorf("%s, %s, %s and %s must be in ranges [%d, %d]",
			QSrcMinPort, QSrcMaxPort, QDstMinPort, QDstMaxPort, common.MinPort, common.MaxPort)
	}

	return nil
}

func invalidArgsExplainMode(args *InArgs, flagset *flag.FlagSet) error {
	if *args.AnalysisType != explainMode && wereExplainParamsSpecified(flagset) {
		return fmt.Errorf("%s, %s, %s, %s and %s can be specified only when analysis-type is %s",
			QProtocol, QSrcMinPort, QSrcMaxPort, QDstMinPort, QDstMaxPort, explainMode)
	}

	if *args.AnalysisType != explainMode {
		return nil
	}

	protocol := strings.ToUpper(*args.QProtocol)
	if protocol != string(common.ProtocolTCP) && protocol != string(common.ProtocolUDP) && protocol != string(common.ProtocolICMP) {
		return fmt.Errorf("wrong connection description protocol '%s'; must be one of: 'TCP, UDP, ICMP'", protocol)
	}
	args.QProtocol = &protocol

	return validRangeConnectionExplainMode(args)
}

func errorInErgs(args *InArgs, flagset *flag.FlagSet) error {
	if !*args.Version && (args.InputConfigFile == nil || *args.InputConfigFile == "") {
		flagset.PrintDefaults()
		return fmt.Errorf("missing parameter: vpc-config")
	}
	if _, ok := supportedAnalysisTypesMap[*args.AnalysisType]; !ok {
		flagset.PrintDefaults()
		return fmt.Errorf("wrong analysis type '%s'; must be one of: '%s'",
			*args.AnalysisType, strings.Join(supportedAnalysisTypesList, separator))
	}
	if !supportedOutputFormatsMap[*args.OutputFormat] {
		flagset.PrintDefaults()
		return fmt.Errorf("wrong output format '%s'; must be one of: '%s'",
			*args.OutputFormat, strings.Join(supportedOutputFormatsList, separator))
	}
	if !slices.Contains(supportedAnalysisTypesMap[*args.AnalysisType], *args.OutputFormat) {
		flagset.PrintDefaults()
		return fmt.Errorf("wrong output format '%s' for analysis type '%s'; must be one of: %s",
			*args.OutputFormat, *args.AnalysisType, strings.Join(supportedAnalysisTypesMap[*args.AnalysisType], separator))
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
	if (*args.AnalysisType == singleSubnet || diffAnalysis) && *args.Grouping {
		return fmt.Errorf("currently %s analysis type does not support grouping", *args.AnalysisType)
	}
	if *args.OutputFormat == JSONFormat && *args.Grouping {
		return fmt.Errorf("json output format is not supported with grouping")
	}
	return nil
}
