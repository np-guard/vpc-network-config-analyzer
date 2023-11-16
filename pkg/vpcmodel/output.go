package vpcmodel

import (
	"errors"
	"os"
	"strings"
)

type OutFormat int64

const (
	JSON OutFormat = iota
	Text
	MD
	CSV
	DRAWIO
	ARCHDRAWIO
	Debug // extended txt format with more details
)

const (
	writeFileMde = 0o600
)

type OutputUseCase int

// ToDo SM: subnets connectivity "only nacl" relevant to diff?
const (
	AllEndpoints    OutputUseCase = iota // connectivity between network interfaces and external ip-blocks
	SingleSubnet                         // connectivity per single subnet with nacl
	AllSubnets                           // connectivity between subnets (consider nacl + pgw)
	AllSubnetsNoPGW                      // connectivity between subnets (consider nacl only)
	SubnetsDiff                          // diff between subnets connectivity of two cfgs (consider nacl + pgw)
	EndpointsDiff                        // diff between vsis connectivity of two cfgs
)

// OutputGenerator captures one vpc config1 with its connectivity analysis results, and implements
// the functionality to generate the analysis output in various formats, for that vpc
type OutputGenerator struct {
	config1        *VPCConfig
	config2        *VPCConfig // specified only when analysis is diff
	outputGrouping bool
	useCase        OutputUseCase
	nodesConn      *VPCConnectivity
	subnetsConn    *VPCsubnetConnectivity
	cfgsDiff       *diffBetweenCfgs
}

func NewOutputGenerator(c1, c2 *VPCConfig, grouping bool, uc OutputUseCase, archOnly bool) (*OutputGenerator, error) {
	res := &OutputGenerator{
		config1:        c1,
		config2:        c2,
		outputGrouping: grouping,
		useCase:        uc,
	}
	if !archOnly {
		if uc == AllEndpoints {
			nodesConn, err := c1.GetVPCNetworkConnectivity(grouping)
			if err != nil {
				return nil, err
			}
			res.nodesConn = nodesConn
		}
		if uc == AllSubnets {
			subnetsConn, err := c1.GetSubnetsConnectivity(true, grouping)
			if err != nil {
				return nil, err
			}
			res.subnetsConn = subnetsConn
		}
		if uc == SubnetsDiff {
			configsForDiff := &ConfigsForDiff{c1, c2, Subnets}
			configsDiff, err := configsForDiff.GetDiff(grouping)
			if err != nil {
				return nil, err
			}
			res.cfgsDiff = configsDiff
		}
		if uc == EndpointsDiff {
			configsForDiff := &ConfigsForDiff{c1, c2, Vsis}
			configsDiff, err := configsForDiff.GetDiff(grouping)
			if err != nil {
				return nil, err
			}
			res.cfgsDiff = configsDiff
		}
	}
	return res, nil
}

// VPCAnalysisOutput captures output per VPC
type VPCAnalysisOutput struct {
	VPCName    string
	Output     string
	jsonStruct interface{}
	format     OutFormat
}

// Generate returns VPCAnalysisOutput for its VPC analysis results
func (o *OutputGenerator) Generate(f OutFormat, outFile string) (*VPCAnalysisOutput, error) {
	var formatter OutputFormatter
	switch f {
	case JSON:
		formatter = &JSONoutputFormatter{}
	case Text:
		formatter = &TextOutputFormatter{}
	case MD:
		formatter = &MDoutputFormatter{}
	case DRAWIO:
		formatter = &DrawioOutputFormatter{}
	case ARCHDRAWIO:
		formatter = &ArchDrawioOutputFormatter{}
	case Debug:
		formatter = &DebugOutputFormatter{}
	default:
		return nil, errors.New("unsupported output format")
	}

	return formatter.WriteOutput(o.config1, o.config2, o.nodesConn, o.subnetsConn, o.cfgsDiff, outFile, o.outputGrouping, o.useCase)
}

type OutputFormatter interface {
	WriteOutput(c1, c2 *VPCConfig, conn *VPCConnectivity, subnetsConn *VPCsubnetConnectivity, subnetsDiff *diffBetweenCfgs,
		outFile string, grouping bool, uc OutputUseCase) (*VPCAnalysisOutput, error)
}

func WriteToFile(content, fileName string) (string, error) {
	if fileName != "" {
		err := os.WriteFile(fileName, []byte(content), writeFileMde)
		return content, err
	}
	return content, nil
}

// AggregateVPCsOutput returns the output string for a list of VPCAnalysisOutput objects
// and writes the output to outFile
func AggregateVPCsOutput(outputList []*VPCAnalysisOutput, f OutFormat, outFile string) (string, error) {
	var res string
	var err error
	switch f {
	case Text, MD, Debug:
		// plain concatenation
		vpcsOut := make([]string, len(outputList))
		for i, o := range outputList {
			vpcsOut[i] = o.Output
		}
		res, err = WriteToFile(strings.Join(vpcsOut, "\n"), outFile)

	case JSON:
		// aggregate to a map from vpc name to its json struct output
		all := map[string]interface{}{}
		for _, o := range outputList {
			all[o.VPCName] = o.jsonStruct
		}
		res, err = writeJSON(all, outFile)
	}
	return res, err
}
