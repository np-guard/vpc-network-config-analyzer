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

const overApproximationSign = " ** "
const statefulMessage = "\nTCP connections for which response is not permitted are marked with" + asterisk + newLine
const overApproximationMessage = "\nconnections marked with " + overApproximationSign +
	" are an over-approximation, not all private IPs have the same connectivity\n"

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
	Synthesis
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
	detailExplain  bool
}

func NewOutputGenerator(cConfigs *MultipleVPCConfigs, grouping bool, uc OutputUseCase,
	archOnly bool, explanationArgs *ExplanationArgs, f OutFormat, lbAbstraction bool) (*OutputGenerator, error) {
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
		switch uc {
		case AllEndpoints:
			for i, vpcConfig := range cConfigs.Configs() {
				nodesConn, err := vpcConfig.GetVPCNetworkConnectivity(grouping, res.lbAbstraction)
				if err != nil {
					return nil, err
				}
				res.nodesConn[i] = nodesConn
			}
		case AllSubnets:
			for i, vpcConfig := range cConfigs.Configs() {
				subnetsConn, err := vpcConfig.GetSubnetsConnectivity(true, grouping)
				if err != nil {
					return nil, err
				}
				res.subnetsConn[i] = subnetsConn
			}
		// diff: only comparison between single vpc configs is supported;
		// thus instead of ranging over configs, takes the single config
		case SubnetsDiff, EndpointsDiff:
			analysisType := Vsis
			if uc == SubnetsDiff {
				analysisType = Subnets
			}
			configsForDiff := &configsForDiff{cConfigs.aConfig(), cConfigs.aConfigToCompare(), analysisType}
			configsDiff, err := configsForDiff.GetDiff()
			if err != nil {
				return nil, err
			}
			res.cfgsDiff = configsDiff
		case Explain:
			connQuery := explanationArgs.GetConnectionSet()
			explanation, err := cConfigs.ExplainConnectivity(explanationArgs.src, explanationArgs.dst, connQuery)
			if err != nil {
				return nil, err
			}
			res.explanation = explanation
			res.detailExplain = explanationArgs.detail
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
	// hasStatelessConn indicates if the connectivity results contain an overApproximated conn
	hasOverApproximatedConn bool
}

// Generate returns a string representing the analysis output for all input VPCs
func (o *OutputGenerator) Generate(f OutFormat, outFile string) (string, error) {
	var formatter OutputFormatter
	switch f {
	case JSON, Text, MD, Synthesis:
		formatter = &serialOutputFormatter{f}
	case DRAWIO, SVG, HTML:
		formatter = newDrawioOutputFormatter(f, o.lbAbstraction)
	case ARCHDRAWIO, ARCHSVG, ARCHHTML:
		formatter = newArchDrawioOutputFormatter(f, o.lbAbstraction)
	default:
		return "", errors.New("unsupported output format")
	}
	return formatter.WriteOutput(o.configs, o.nodesConn, o.subnetsConn, o.cfgsDiff,
		outFile, o.outputGrouping, o.useCase, o.explanation, o.detailExplain)
}

// SingleVpcOutputFormatter is an interface for a formatter that can handle only one vpc
// this interface is implemented by textOutputFormatter, jsonOutputFormatter, mdOutputFormatter
type SingleVpcOutputFormatter interface {
	WriteOutput(c1, c2 *VPCConfig, conn *VPCConnectivity,
		subnetsConn *VPCsubnetConnectivity, subnetsDiff *diffBetweenCfgs,
		outFile string, grouping bool, uc OutputUseCase, explainStruct *Explanation, detailExplain bool) (*SingleAnalysisOutput, error)
}

// OutputFormatter is an interface for formatter that handle multi vpcs.
// implemented by serialOutputFormatter and drawioOutputFormatter
type OutputFormatter interface {
	WriteOutput(cConfigs *MultipleVPCConfigs, conn map[string]*VPCConnectivity,
		subnetsConn map[string]*VPCsubnetConnectivity, subnetsDiff *diffBetweenCfgs,
		outFile string, grouping bool, uc OutputUseCase, explainStruct *Explanation, detailExplain bool) (string, error)
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
	case Synthesis:
		return &SynthesisOutputFormatter{}
	}
	return nil
}

func (of *serialOutputFormatter) WriteOutput(cConfigs *MultipleVPCConfigs, conns map[string]*VPCConnectivity,
	subnetsConns map[string]*VPCsubnetConnectivity, configsDiff *diffBetweenCfgs,
	outFile string, grouping bool, uc OutputUseCase,
	explainStruct *Explanation, detailExplain bool) (string, error) {
	singleVPCAnalysis := uc == EndpointsDiff || uc == SubnetsDiff || uc == Explain
	if !singleVPCAnalysis {
		outputPerVPC := make([]*SingleAnalysisOutput, len(cConfigs.Configs()))
		i := 0
		for uid, vpcConfig := range cConfigs.Configs() {
			vpcAnalysisOutput, err :=
				of.createSingleVpcFormatter().WriteOutput(vpcConfig, nil, conns[uid], subnetsConns[uid],
					configsDiff, "", grouping, uc, explainStruct, detailExplain)
			if err != nil {
				return "", err
			}
			outputPerVPC[i] = vpcAnalysisOutput
			i++
		}
		return of.AggregateVPCsOutput(outputPerVPC, uc, outFile)
	}
	// singleVPCAnalysis: either diff or explain. In either case conn and subnet conn are non-relevant, thus passing nil
	// diff compares between two single vpc configs
	// explain works on a specific config, either single or multiple; the relevant config for explain is kept
	// in its structs, thus the configs passed here are non-relevant for it; the flow is such that valid main config must be passed,
	// also for explain (even though it does not affect the output)
	var toCompareConfig *VPCConfig
	if uc == EndpointsDiff || uc == SubnetsDiff {
		toCompareConfig = cConfigs.aConfigToCompare()
	}
	vpcAnalysisOutput, err :=
		of.createSingleVpcFormatter().WriteOutput(cConfigs.aConfig(), toCompareConfig, nil, nil,
			configsDiff, "", grouping, uc, explainStruct, detailExplain)
	if err != nil {
		return "", err
	}
	// its diff or explain mode, we have only one vpc on each map:
	return of.WriteDiffOrExplainOutput(vpcAnalysisOutput, uc, outFile)
}

func WriteToFile(content, fileName string) (string, error) {
	if fileName != "" {
		err := os.WriteFile(fileName, []byte(content), writeFileMde)
		return content, err
	}
	return content, nil
}

// getAsteriskDetails returns:
// 1. The info message regarding non-responsive conns  in the output, when relevant
// 2. The info message regarding over-approximated conns, when relevant
func getAsteriskDetails(uc OutputUseCase, hasStatelessConn, hasOverApproximatedConn bool, outFormat OutFormat) string {
	res := ""
	if uc != SingleSubnet && (outFormat == Text || outFormat == MD) {
		if hasStatelessConn {
			res += statefulMessage
		}
		if hasOverApproximatedConn {
			res += overApproximationMessage
		}
	}
	return res
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
	case Text, MD:
		// plain concatenation
		vpcsOut := make([]string, len(outputList))
		hasStatelessConn := false
		hasOverApproximatedConn := false
		for i, o := range outputList {
			vpcsOut[i] = o.Output
			if o.hasStatelessConn {
				hasStatelessConn = true
			}
			if o.hasOverApproximatedConn {
				hasOverApproximatedConn = true
			}
		}
		sort.Strings(vpcsOut)
		infoMessage := getAsteriskDetails(uc, hasStatelessConn, hasOverApproximatedConn, of.outFormat)
		res, err = WriteToFile(strings.Join(vpcsOut, "\n")+infoMessage, outFile)

	case JSON:
		all := map[string]interface{}{}
		for _, o := range outputList {
			all[o.VPC1Name] = o.jsonStruct
		}
		res, err = writeJSON(all, outFile)
	case Synthesis:
		// in synthesis format we need to follow json spec schema
		// https://github.com/np-guard/models/blob/main/spec_schema.json
		res, err = writeJSON(outputList[0].jsonStruct, outFile)
	}
	return res, err
}

// WriteDiffOrExplainOutput actual writing the output into file, with required format adjustments
func (of *serialOutputFormatter) WriteDiffOrExplainOutput(output *SingleAnalysisOutput, uc OutputUseCase, outFile string) (string, error) {
	var res string
	var err error
	switch of.outFormat {
	case Text, MD: // currently, return out as is
		infoMessage := getAsteriskDetails(uc, output.hasStatelessConn, output.hasOverApproximatedConn, of.outFormat)
		res, err = WriteToFile(output.Output+infoMessage, outFile)
	case JSON:
		all := map[string]interface{}{}
		head := fmt.Sprintf("diff-%s-%s", output.VPC1Name, output.VPC2Name)
		all[head] = output.jsonStruct
		res, err = writeJSON(all, outFile)
	}
	return res, err
}
