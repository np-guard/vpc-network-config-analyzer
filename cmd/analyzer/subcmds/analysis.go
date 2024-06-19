/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/ibmvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

//nolint:gocritic  // temporary version, wip
func routingAnalysis(inArgs *inArgs) error {
	vpcConfigs, err := buildConfigs(inArgs)
	if err != nil {
		return err
	}

	analyzer := ibmvpc.NewGlobalRTAnalyzer(vpcConfigs)
	pairs := vpcConfigs.GetInternalNodePairs()
	for _, pair := range pairs {
		path, err := analyzer.GetRoutingPath(pair.Src.(vpcmodel.InternalNodeIntf), pair.Dst.IPBlock())
		if err != nil {
			return err
		}
		fmt.Printf("path for src %s, dst %s:\n", pair.Src.CidrOrAddress(), pair.Dst.CidrOrAddress())
		fmt.Println(path.String())
		fmt.Println("")
	}
	return nil

	/*
		current output:

		path for src 10.1.15.4, dst 192.168.0.4:
		NetworkInterface - tvpc-transit-z1-worker[10.1.15.4] -> TGW - tvpc-tgw-link -> NetworkInterface - tvpc-enterprise-z1-worker[192.168.0.4]

		path for src 192.168.0.4, dst 10.1.15.4:
		NetworkInterface - tvpc-enterprise-z1-worker[192.168.0.4] -> TGW - tvpc-tgw-link -> NetworkInterface - tvpc-transit-z1-worker[10.1.15.4]

		path for src 10.1.0.4, dst 192.168.0.4:
		NetworkInterface - tvpc-spoke0-z1-worker[10.1.0.4] -> TGW - tvpc-tgw -> nextHop: 10.3.15.196 [origDest: 192.168.0.4]

		path for src 10.3.15.196, dst 192.168.0.4:
		NetworkInterface - tvpc-fw-z3-s3-0[10.3.15.196] -> TGW - tvpc-tgw-link -> NetworkInterface - tvpc-enterprise-z1-worker[192.168.0.4]

	*/
	/*srcDstPairs := []struct {
		src string
		dst string
	}{
		{
			src: "10.1.15.4",
			dst: "192.168.0.4",
		},
		{
			dst: "10.1.15.4",
			src: "192.168.0.4",
		},
		{
			src: "10.1.0.4",    // spoke vpc
			dst: "192.168.0.4", // enterprise vpc
		},
		{
			src: "10.3.15.196",
			dst: "192.168.0.4",
		},

	}
	for _, pair := range srcDstPairs {
		srcNode, err1 := vpcConfigs.GetInternalNodeFromAddress(pair.src)
		dstIPBlock, err2 := ipblock.FromIPAddress(pair.dst)
		path, err3 := analyzer.GetRoutingPath(srcNode, dstIPBlock)
		if err := errors.Join(err1, err2, err3); err != nil {
			fmt.Printf("err: %s", err.Error())
			return err
		}
		fmt.Printf("path for src %s, dst %s:\n", pair.src, pair.dst)
		fmt.Println(path.String())
		fmt.Println("")
	}
	return nil*/
}

func analysisVPCConfigs(cmd *cobra.Command, inArgs *inArgs, analysisType vpcmodel.OutputUseCase) error {
	cmd.SilenceUsage = true  // if we got this far, flags are syntactically correct, so no need to print usage
	cmd.SilenceErrors = true // also, error will be printed to logger in main(), so no need for cobra to also print it

	vpcConfigs, err := buildConfigs(inArgs)
	if err != nil {
		return err
	}
	outFormat := inArgs.outputFormat.ToModelFormat()
	// todo - the lbAbstraction should be derived from a flag "debug", when we will have one
	lbAbstraction := outFormat != vpcmodel.Debug
	og, err := vpcmodel.NewOutputGenerator(vpcConfigs,
		inArgs.grouping,
		analysisType,
		false,
		inArgs.explanationArgs, outFormat, lbAbstraction)
	if err != nil {
		return err
	}

	analysisOut, err := og.Generate(outFormat, inArgs.outputFile)
	if err != nil {
		return fmt.Errorf("output generation error: %w", err)
	}

	fmt.Println(analysisOut)
	return nil
}
