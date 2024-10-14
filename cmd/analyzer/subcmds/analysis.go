/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"errors"
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/ibmvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func getSrcDstPairs(src, dst string, vpcConfigs *vpcmodel.MultipleVPCConfigs) (res []common.Pair[vpcmodel.Node], err error) {
	switch {
	case src != "" && dst != "":
		// TODO: support input src/dst of name or external address , not only internal address
		srcNode, err1 := vpcConfigs.GetInternalNodeFromAddress(src)
		dstNode, err2 := vpcConfigs.GetInternalNodeFromAddress(dst)
		if errors.Join(err1, err2) != nil {
			return nil, errors.Join(err1, err2)
		}
		return []common.Pair[vpcmodel.Node]{{Src: srcNode.(vpcmodel.Node), Dst: dstNode.(vpcmodel.Node)}}, nil
	case src == "" && dst == "":
		return vpcConfigs.GetInternalNodePairs(), nil
	default:
		return nil, fmt.Errorf("currently supporting either both src/dst specified, or none specified")
	}
}

func routingAnalysis(inArgs *inArgs) error {
	vpcConfigs, err := buildConfigs(inArgs)
	if err != nil {
		return err
	}

	analyzer := ibmvpc.NewGlobalRTAnalyzer(vpcConfigs)
	src, dst := inArgs.eSrc, inArgs.eDst

	srcDstPairs, err := getSrcDstPairs(src, dst, vpcConfigs)
	if err != nil {
		return err
	}
	for _, pair := range srcDstPairs {
		if err := pairRoutingAnalysis(pair.Src, pair.Dst, analyzer); err != nil {
			return err
		}
	}

	return nil
}

func pairRoutingAnalysis(src, dst vpcmodel.Node, analyzer *ibmvpc.GlobalRTAnalyzer) error {
	srcNode := src.(vpcmodel.InternalNodeIntf)
	dstIPBlock := dst.IPBlock()
	path, err := analyzer.GetRoutingPath(srcNode, dstIPBlock)
	if err != nil {
		fmt.Printf("err: %s", err.Error())
		return err
	}
	fmt.Printf("path for src %s, dst %s:\n", src.IPBlock().String(), dstIPBlock.String())
	fmt.Println(path.String())
	fmt.Println("")
	return nil
}

func analysisVPCConfigs(cmd *cobra.Command, inArgs *inArgs, analysisType vpcmodel.OutputUseCase) error {
	cmd.SilenceUsage = true  // if we got this far, flags are syntactically correct, so no need to print usage
	cmd.SilenceErrors = true // also, error will be printed to logger in main(), so no need for cobra to also print it

	vpcConfigs, err := buildConfigs(inArgs)
	if err != nil {
		return err
	}
	outFormat := inArgs.outputFormat.ToModelFormat()
	consistencyEdgesExternal := slices.Contains([]vpcmodel.OutFormat{vpcmodel.DRAWIO, vpcmodel.SVG, vpcmodel.HTML},
		outFormat)
	var groupingType int
	switch {
	case !inArgs.grouping && !consistencyEdgesExternal:
		groupingType = vpcmodel.NoGroupingNoConsistencyEdges
	case !inArgs.grouping && consistencyEdgesExternal:
		groupingType = vpcmodel.NoGroupingWithConsistencyEdges
	case inArgs.grouping && !consistencyEdgesExternal:
		groupingType = vpcmodel.GroupingNoConsistencyEdges
	default:
		groupingType = vpcmodel.GroupingWithConsistencyEdges
	}
	og, err := vpcmodel.NewOutputGenerator(vpcConfigs,
		groupingType,
		analysisType,
		false,
		inArgs.explanationArgs, outFormat, inArgs.lbAbstraction)
	if err != nil {
		return err
	}

	analysisOut, err := og.Generate(outFormat, inArgs.outputFile)
	if err != nil {
		return fmt.Errorf("output generation error: %w", err)
	}

	if inArgs.outputFile == "" {
		fmt.Println(analysisOut)
	}
	return nil
}
