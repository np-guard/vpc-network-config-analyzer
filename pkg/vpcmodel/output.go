package vpcmodel

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

type OutFormat int64

const asteriskDetails = "\nconnections are stateful unless marked with *\n"

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
	Explain                              // explain specified connectivity, given src,dst and connection
)

// OutputGenerator captures one vpc config1 with its connectivity analysis results, and implements
// the functionality to generate the analysis output in various formats, for that vpc
type OutputGenerator struct {
	config1        map[string]*VPCConfig
	config2        map[string]*VPCConfig // specified only when analysis is diff
	outputGrouping bool
	useCase        OutputUseCase
	nodesConn      map[string]*VPCConnectivity
	subnetsConn    map[string]*VPCsubnetConnectivity
	cfgsDiff       *diffBetweenCfgs
}

func NewOutputGenerator(c1, c2 map[string]*VPCConfig, grouping bool, uc OutputUseCase, archOnly bool) (*OutputGenerator, error) {
	res := &OutputGenerator{
		config1:        c1,
		config2:        c2,
		outputGrouping: grouping,
		useCase:        uc,
		nodesConn:      map[string]*VPCConnectivity{},
		subnetsConn:    map[string]*VPCsubnetConnectivity{},
	}
	if !archOnly {
		for i := range c1 {
			if uc == AllEndpoints {
				nodesConn, err := c1[i].GetVPCNetworkConnectivity(grouping)
				if err != nil {
					return nil, err
				}
				res.nodesConn[i] = nodesConn
			}
			if uc == AllSubnets {
				subnetsConn, err := c1[i].GetSubnetsConnectivity(true, grouping)
				if err != nil {
					return nil, err
				}
				res.subnetsConn[i] = subnetsConn
			}
			if uc == SubnetsDiff {
				configsForDiff := &configsForDiff{c1[i], c2[i], Subnets}
				configsDiff, err := configsForDiff.GetDiff()
				if err != nil {
					return nil, err
				}
				res.cfgsDiff = configsDiff
			}
			if uc == EndpointsDiff {
				configsForDiff := &configsForDiff{c1[i], c2[i], Vsis}
				configsDiff, err := configsForDiff.GetDiff()
				if err != nil {
					return nil, err
				}
				res.cfgsDiff = configsDiff
			}
		}
	}
	return res, nil
}

// SingleAnalysisOutput captures output per connectivity analysis of a single VPC,  or per semantic diff between 2 VPCs
// in the former case VPC2Name will be empty
type SingleAnalysisOutput struct {
	VPC1Name   string
	VPC2Name   string
	Output     string
	jsonStruct interface{}
	format     OutFormat
	// hasStatelessConn indicates if the connectivity results contain a stateless conn
	hasStatelessConn bool
}

// Generate returns a string representing the analysis output for all input VPCs
func (o *OutputGenerator) Generate(f OutFormat, outFile string) (string, error) {
	var formatter OutputFormatter
	switch f {
	case JSON, Text, MD, Debug:
		formatter = &serialOutputFormatter{f}
	case DRAWIO:
		formatter = &DrawioOutputFormatter{}
	case ARCHDRAWIO:
		formatter = &ArchDrawioOutputFormatter{}
	default:
		return "", errors.New("unsupported output format")
	}
	return formatter.WriteOutput(o.config1, o.config2, o.nodesConn, o.subnetsConn, o.cfgsDiff, outFile, o.outputGrouping, o.useCase)
}

// SingleVpcOutputFormatter is an interface for a formatter that can handle only one vpc
// this interface is implemented by textOutputFormatter, jsonOutputFormatter, mdOutputFormatter
type SingleVpcOutputFormatter interface {
	WriteOutput(c1, c2 *VPCConfig, conn *VPCConnectivity,
		subnetsConn *VPCsubnetConnectivity, subnetsDiff *diffBetweenCfgs,
		outFile string, grouping bool, uc OutputUseCase) (*SingleAnalysisOutput, error)
}

// OutputFormatter is an interface for formatter that handle multi vpcs.
// implemented by serialOutputFormatter and drawioOutputFormatter
type OutputFormatter interface {
	WriteOutput(c1, c2 map[string]*VPCConfig, conn map[string]*VPCConnectivity,
		subnetsConn map[string]*VPCsubnetConnectivity, subnetsDiff *diffBetweenCfgs,
		outFile string, grouping bool, uc OutputUseCase) (string, error)
}

// serialOutputFormatter is the formatter for json, md and txt formats.
// serialOutputFormatter implements the interface OutputFormatter.
// the main flow of WriteOutput() of serialOutputFormatter is:
// 1. for each vpc, create and use a SingleVpcOutputFormatter to create a SingleAnalysisOutput ,
// 2. aggregate the SingleAnalysisOutputs to one output
type serialOutputFormatter struct {
	outFormat OutFormat
}

func (of *serialOutputFormatter) createSingleVpcFormatter() SingleVpcOutputFormatter {
	switch of.outFormat {
	case JSON:
		return &JSONoutputFormatter{}
	case Text:
		return &TextOutputFormatter{}
	case MD:
		return &MDoutputFormatter{}
	case Debug:
		return &DebugOutputFormatter{}
	}
	return nil
}

func (of *serialOutputFormatter) WriteOutput(c1, c2 map[string]*VPCConfig, conns map[string]*VPCConnectivity,
	subnetsConns map[string]*VPCsubnetConnectivity, subnetsDiff *diffBetweenCfgs,
	outFile string, grouping bool, uc OutputUseCase) (string, error) {
	diffAnalysis := uc == EndpointsDiff || uc == SubnetsDiff
	if !diffAnalysis {
		outputPerVPC := make([]*SingleAnalysisOutput, len(c1))
		i := 0
		for name := range c1 {
			vpcAnalysisOutput, err2 :=
				of.createSingleVpcFormatter().WriteOutput(c1[name], nil, conns[name], subnetsConns[name], subnetsDiff, "", grouping, uc)
			if err2 != nil {
				return "", err2
			}
			outputPerVPC[i] = vpcAnalysisOutput
			i++
		}
		return of.AggregateVPCsOutput(outputPerVPC, uc, outFile)
	}
	// its a diff mode, we have only one vpc on each map:
	name, _ := common.AnyMapEntry(c1)
	vpcAnalysisOutput, err2 :=
		of.createSingleVpcFormatter().WriteOutput(c1[name], c2[name], conns[name], subnetsConns[name], subnetsDiff, "", grouping, uc)
	if err2 != nil {
		return "", err2
	}
	return of.WriteDiffOutput(vpcAnalysisOutput, uc, outFile)
}

func WriteToFile(content, fileName string) (string, error) {
	if fileName != "" {
		err := os.WriteFile(fileName, []byte(content), writeFileMde)
		return content, err
	}
	return content, nil
}

// getAsteriskDetails returns the info message about how non stateful conns are marked in the output, when relevant
func getAsteriskDetails(uc OutputUseCase, hasStatelessConn bool, outFormat OutFormat) string {
	if uc != SingleSubnet && (outFormat == Text || outFormat == MD || outFormat == Debug) && hasStatelessConn {
		return asteriskDetails
	}

	return ""
}

// AggregateVPCsOutput returns the output string for a list of SingleAnalysisOutput objects
// and writes the output to outFile
func (of *serialOutputFormatter) AggregateVPCsOutput(outputList []*SingleAnalysisOutput, uc OutputUseCase, outFile string) (string, error) {
	var res string
	var err error

	sort.Slice(outputList, func(i, j int) bool {
		return outputList[i].VPC1Name < outputList[j].VPC1Name
	})

	switch of.outFormat {
	case Text, MD, Debug:
		// plain concatenation
		vpcsOut := make([]string, len(outputList))
		hasStatelessConn := false
		for i, o := range outputList {
			vpcsOut[i] = o.Output
			if o.hasStatelessConn {
				hasStatelessConn = true
			}
		}
		sort.Strings(vpcsOut)
		infoMessage := getAsteriskDetails(uc, hasStatelessConn, of.outFormat)
		res, err = WriteToFile(strings.Join(vpcsOut, "\n")+infoMessage, outFile)

	case JSON:
		all := map[string]interface{}{}
		for _, o := range outputList {
			all[o.VPC1Name] = o.jsonStruct
		}
		res, err = writeJSON(all, outFile)
	}
	return res, err
}

// WriteDiffOutput actual writing the output into file, with required format adjustments
func (of *serialOutputFormatter) WriteDiffOutput(output *SingleAnalysisOutput, uc OutputUseCase, outFile string) (string, error) {
	var res string
	var err error
	switch of.outFormat {
	case Text, MD, Debug: // currently, return out as is
		infoMessage := getAsteriskDetails(uc, output.hasStatelessConn, of.outFormat)
		res, err = WriteToFile(output.Output+infoMessage, outFile)
	case JSON:
		all := map[string]interface{}{}
		head := fmt.Sprintf("diff-%s-%s", output.VPC1Name, output.VPC2Name)
		all[head] = output.jsonStruct
		res, err = writeJSON(all, outFile)
	}
	return res, err
}
