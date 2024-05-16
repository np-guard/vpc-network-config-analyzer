/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
)

type OutFormat int64

const asteriskDetails = "\nconnections are stateful (on TCP) unless marked with *\n"

const (
	JSON OutFormat = iota
	Text
	MD
	CSV
	DRAWIO
	ARCHDRAWIO
	SVG
	ARCHSVG
	HTML
	ARCHHTML
	Debug // extended txt format with more details
)

const (
	writeFileMde = 0o600
)

type OutputUseCase int

// ToDo SM: subnets connectivity "only nacl" relevant to diff?
const (
	InvalidUseCase  OutputUseCase = iota // A place holder for an illegal value
	AllEndpoints                         // connectivity between network interfaces and external ip-blocks
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
	configs        *MultipleVPCConfigs
	outputGrouping bool
	lbAbstraction  bool
	useCase        OutputUseCase
	nodesConn      map[string]*VPCConnectivity
	subnetsConn    map[string]*VPCsubnetConnectivity
	cfgsDiff       *diffBetweenCfgs
	explanation    *Explanation
}

func NewOutputGenerator(cConfigs *MultipleVPCConfigs, grouping bool, uc OutputUseCase,
	archOnly bool, explanationArgs *ExplanationArgs, f OutFormat) (*OutputGenerator, error) {
	// todo -  for now, we always abstract lb.
	// 1. should it be a user input?
	// 2. if not abstracting, make sure we do present only the original private IP
	lbAbstraction := true
	res := &OutputGenerator{
		configs:        cConfigs,
		outputGrouping: grouping,
		lbAbstraction:  lbAbstraction,
		useCase:        uc,
		nodesConn:      map[string]*VPCConnectivity{},
		subnetsConn:    map[string]*VPCsubnetConnectivity{},
	}
	graphicFormat := slices.Contains([]OutFormat{DRAWIO, ARCHDRAWIO, SVG, ARCHSVG, HTML, ARCHHTML}, f)
	archOnlyFormat := slices.Contains([]OutFormat{ARCHDRAWIO, ARCHSVG, ARCHHTML}, f)
	if !archOnlyFormat {
		if uc == Explain {
			connQuery := explanationArgs.GetConnectionSet()
			explanation, err := cConfigs.ExplainConnectivity(explanationArgs.src, explanationArgs.dst, connQuery)
			if err != nil {
				return nil, err
			}
			res.explanation = explanation
		}
		for i, vpcConfig := range cConfigs.Configs() {
			if uc == AllEndpoints {
				nodesConn, err := vpcConfig.GetVPCNetworkConnectivity(grouping, res.lbAbstraction)
				if err != nil {
					return nil, err
				}
				res.nodesConn[i] = nodesConn
			}
			if uc == AllSubnets {
				subnetsConn, err := vpcConfig.GetSubnetsConnectivity(true, grouping)
				if err != nil {
					return nil, err
				}
				res.subnetsConn[i] = subnetsConn
			}
			if uc == SubnetsDiff {
				configsForDiff := &configsForDiff{vpcConfig, cConfigs.ConfigToCompare(i), Subnets}
				configsDiff, err := configsForDiff.GetDiff()
				if err != nil {
					return nil, err
				}
				res.cfgsDiff = configsDiff
			}
			if uc == EndpointsDiff {
				configsForDiff := &configsForDiff{vpcConfig, cConfigs.ConfigToCompare(i), Vsis}
				configsDiff, err := configsForDiff.GetDiff()
				if err != nil {
					return nil, err
				}
				res.cfgsDiff = configsDiff
			}
		}
	}
	// only Graphic formats has a multi vpc common presentation
	if graphicFormat {
		unifyMultiVPC(cConfigs, res.nodesConn, res.subnetsConn, uc)
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
	case DRAWIO, SVG, HTML:
		formatter = newDrawioOutputFormatter(f, o.lbAbstraction)
	case ARCHDRAWIO, ARCHSVG, ARCHHTML:
		formatter = newArchDrawioOutputFormatter(f, o.lbAbstraction)
	default:
		return "", errors.New("unsupported output format")
	}
	return formatter.WriteOutput(o.configs, o.nodesConn, o.subnetsConn, o.cfgsDiff,
		outFile, o.outputGrouping, o.useCase, o.explanation)
}

// SingleVpcOutputFormatter is an interface for a formatter that can handle only one vpc
// this interface is implemented by textOutputFormatter, jsonOutputFormatter, mdOutputFormatter
type SingleVpcOutputFormatter interface {
	WriteOutput(c1, c2 *VPCConfig, conn *VPCConnectivity,
		subnetsConn *VPCsubnetConnectivity, subnetsDiff *diffBetweenCfgs,
		outFile string, grouping bool, uc OutputUseCase, explainStruct *Explanation) (*SingleAnalysisOutput, error)
}

// OutputFormatter is an interface for formatter that handle multi vpcs.
// implemented by serialOutputFormatter and drawioOutputFormatter
type OutputFormatter interface {
	WriteOutput(cConfigs *MultipleVPCConfigs, conn map[string]*VPCConnectivity,
		subnetsConn map[string]*VPCsubnetConnectivity, subnetsDiff *diffBetweenCfgs,
		outFile string, grouping bool, uc OutputUseCase, explainStruct *Explanation) (string, error)
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

func (of *serialOutputFormatter) WriteOutput(cConfigs *MultipleVPCConfigs, conns map[string]*VPCConnectivity,
	subnetsConns map[string]*VPCsubnetConnectivity, subnetsDiff *diffBetweenCfgs,
	outFile string, grouping bool, uc OutputUseCase, explainStruct *Explanation) (string, error) {
	singleVPCAnalysis := uc == EndpointsDiff || uc == SubnetsDiff || uc == Explain
	if !singleVPCAnalysis {
		outputPerVPC := make([]*SingleAnalysisOutput, len(cConfigs.Configs()))
		i := 0
		for uid, vpcConfig := range cConfigs.Configs() {
			vpcAnalysisOutput, err2 :=
				of.createSingleVpcFormatter().WriteOutput(vpcConfig, nil, conns[uid], subnetsConns[uid],
					subnetsDiff, "", grouping, uc, explainStruct)
			if err2 != nil {
				return "", err2
			}
			outputPerVPC[i] = vpcAnalysisOutput
			i++
		}
		return of.AggregateVPCsOutput(outputPerVPC, uc, outFile)
	}
	for uid, vpcConfig := range cConfigs.Configs() {
		vpcAnalysisOutput, err2 :=
			of.createSingleVpcFormatter().WriteOutput(vpcConfig, cConfigs.ConfigToCompare(uid), conns[uid], subnetsConns[uid],
				subnetsDiff, "", grouping, uc, explainStruct)
		if err2 != nil {
			return "", err2
		}
		// its diff or explain mode, we have only one vpc on each map:
		return of.WriteDiffOrExplainOutput(vpcAnalysisOutput, uc, outFile)
	}
	return "", nil
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

// WriteDiffOrExplainOutput actual writing the output into file, with required format adjustments
func (of *serialOutputFormatter) WriteDiffOrExplainOutput(output *SingleAnalysisOutput, uc OutputUseCase, outFile string) (string, error) {
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
