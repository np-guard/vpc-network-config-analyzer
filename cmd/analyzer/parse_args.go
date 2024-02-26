package main

import (
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/cloud-resource-collector/pkg/factory"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

type regionList []string

func (dp *regionList) String() string {
	return fmt.Sprintln(*dp)
}

func (dp *regionList) Set(region string) error {
	*dp = append(*dp, region)
	return nil
}

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
	ESrc                  *string
	EDst                  *string
	EProtocol             *string
	ESrcMinPort           *int64
	ESrcMaxPort           *int64
	EDstMinPort           *int64
	EDstMaxPort           *int64
	Provider              *string
	RegionList            regionList
	ResourceGroup         *string
	DumpResources         *string
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
	ESrc:                  true,
	EDst:                  true,
	EProtocol:             true,
	ESrcMinPort:           true,
	ESrcMaxPort:           true,
	EDstMinPort:           true,
	EDstMaxPort:           true,
	Provider:              true,
	RegionList:            true,
	ResourceGroup:         true,
	DumpResources:         true,
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
	explainMode:      {TEXTFormat, DEBUGFormat},
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

const srcDstUsage = "endpoint for explanation; can be specified as a VSI name/CRN or an internal/external IP-address/CIDR"

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
	args.ESrc = flagset.String(ESrc, "", "Source "+srcDstUsage)
	args.EDst = flagset.String(EDst, "", "Destination "+srcDstUsage)
	args.EProtocol = flagset.String(EProtocol, "", "Protocol for connection description")
	args.ESrcMinPort = flagset.Int64(ESrcMinPort, common.MinPort, "Minimum source port for connection description")
	args.ESrcMaxPort = flagset.Int64(ESrcMaxPort, common.MaxPort, "Maximum source port for connection description")
	args.EDstMinPort = flagset.Int64(EDstMinPort, common.MinPort, "Minimum destination port for connection description")
	args.EDstMaxPort = flagset.Int64(EDstMaxPort, common.MaxPort, "Maximum destination port for connection description")
	args.Provider = flagset.String(Provider, "", "Collect resources from an account in this cloud provider")
	args.ResourceGroup = flagset.String(ResourceGroup, "", "Resource group id or name from which to collect resources")
	flagset.Var(&args.RegionList, "region", "Cloud region from which to collect resources")
	args.DumpResources = flagset.String(DumpResources, "", "File path to store resources collected from the cloud provider")

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
	err = errorInArgs(&args, flagset)
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

func wereExplainParamsSpecified(flagset *flag.FlagSet, flagNames []string) bool {
	specified := false
	for i := 0; i < len(flagNames); i++ {
		if wasFlagSpecified(flagNames[i], flagset) {
			specified = true
		}
	}

	return specified
}

func PortInRange(port int64) bool {
	if port > common.MaxPort || port < common.MinPort {
		return false
	}

	return true
}

func minMaxValidity(minPort, maxPort int64, minPortName, maxPortName string) error {
	if minPort > maxPort {
		return fmt.Errorf("%s %d must not be larger than %s %d", minPortName, minPort, maxPortName, maxPort)
	}

	return nil
}

func validRangeConnectionExplainMode(args *InArgs) error {
	err := minMaxValidity(*args.ESrcMinPort, *args.ESrcMaxPort, ESrcMinPort, ESrcMaxPort)
	if err != nil {
		return err
	}
	err = minMaxValidity(*args.EDstMinPort, *args.EDstMaxPort, EDstMinPort, EDstMaxPort)
	if err != nil {
		return err
	}

	if !PortInRange(*args.ESrcMinPort) || !PortInRange(*args.ESrcMaxPort) ||
		!PortInRange(*args.EDstMinPort) || !PortInRange(*args.EDstMaxPort) {
		return fmt.Errorf("%s, %s, %s and %s must be in ranges [%d, %d]",
			ESrcMinPort, ESrcMaxPort, EDstMinPort, EDstMaxPort, common.MinPort, common.MaxPort)
	}

	return nil
}

func invalidArgsExplainMode(args *InArgs, flagset *flag.FlagSet) error {
	if *args.AnalysisType != explainMode {
		if wereExplainParamsSpecified(flagset, []string{ESrc, EDst, EProtocol, ESrcMinPort, ESrcMaxPort, EDstMinPort, EDstMaxPort, explainMode}) {
			return fmt.Errorf("explainability related params %s, %s, %s, %s, %s, %s and %s"+
				"can be specified only in explain mode: analysis-type equals %s",
				ESrc, EDst, EProtocol, ESrcMinPort, ESrcMaxPort, EDstMinPort, EDstMaxPort, explainMode)
		}
		return nil
	}

	if *args.ESrc == "" || *args.EDst == "" {
		return fmt.Errorf("please specify %s and %s network_interface / external ip you want to explain connectivity for", ESrc, EDst)
	}

	if *args.EProtocol == "" {
		if wereExplainParamsSpecified(flagset, []string{EProtocol, ESrcMinPort, ESrcMaxPort, EDstMinPort, EDstMaxPort, explainMode}) {
			return fmt.Errorf("protocol must be specified when querying a specific connection")
		}
		return nil
	}

	protocol := strings.ToUpper(*args.EProtocol)
	if protocol != string(common.ProtocolTCP) && protocol != string(common.ProtocolUDP) && protocol != string(common.ProtocolICMP) {
		return fmt.Errorf("wrong connection description protocol '%s'; must be one of: 'TCP, UDP, ICMP'", protocol)
	}
	args.EProtocol = &protocol

	return validRangeConnectionExplainMode(args)
}

func invalidArgsConfigFile(args *InArgs, flagset *flag.FlagSet) error {
	if !*args.Version && (args.InputConfigFile == nil || *args.InputConfigFile == "") && (args.Provider == nil || *args.Provider == "") {
		flagset.PrintDefaults()
		return fmt.Errorf("missing parameter: either vpc-config flag or provider flag must be specified")
	}
	if *args.InputConfigFile != "" && *args.Provider != "" {
		flagset.PrintDefaults()
		return fmt.Errorf("error in parameters: vpc-config flag and provider flag cannot be specified together")
	}
	if *args.Provider == "" && *args.DumpResources != "" {
		flagset.PrintDefaults()
		return fmt.Errorf("error in parameters: dump-resources flag can only be specified in combination with provider flag")
	}

	return nil
}

func errorInArgs(args *InArgs, flagset *flag.FlagSet) error {
	err := invalidArgsConfigFile(args, flagset)
	if err != nil {
		return err
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
	if (len(args.RegionList) != 0 || *args.ResourceGroup != "") && *args.Provider == "" {
		return fmt.Errorf("error in parameters: resource-group and region can only be specified in combination with provider flag")
	}
	if *args.Provider != factory.IBM && *args.Provider != "" {
		return fmt.Errorf("unsupported provider: %s", *args.Provider)
	}
	return nil
}
