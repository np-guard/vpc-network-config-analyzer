/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"errors"
	"fmt"
)

type TextOutputFormatter struct {
}

func multipleVPCsConfigHeader(c *VPCConfig) (string, error) {
	if len(c.RoutingResources) != 1 {
		return "", errors.New("unexpected config of multiple VPCs connected by TGW, missing TGW resource")
	}
	tgw := c.RoutingResources[0]
	return fmt.Sprintf("Connectivity between VPCs connected by TGW %s (UID: %s)\n", tgw.Name(), tgw.UID()), nil
}

func headerOfAnalyzedVPC(uc OutputUseCase, vpcName, vpc2Name string, c1 *VPCConfig,
	explanation *Explanation, diffSameUID bool) (string, error) {
	switch uc {
	case AllEndpoints:
		if c1.IsMultipleVPCsConfig {
			return multipleVPCsConfigHeader(c1)
		}
		return fmt.Sprintf("Endpoint connectivity for VPC %s\n", vpcName), nil
	case AllSubnets:
		if c1.IsMultipleVPCsConfig {
			return multipleVPCsConfigHeader(c1)
		}
		return fmt.Sprintf("Subnet connectivity for VPC %s\n", vpcName), nil
	case SingleSubnet:
		if c1.IsMultipleVPCsConfig {
			return multipleVPCsConfigHeader(c1)
		}
		return fmt.Sprintf("Connectivity per subnet for VPC %s\n", vpcName), nil
	case SubnetsDiff, EndpointsDiff:
		header := fmt.Sprintf("Connectivity diff between VPC %s and VPC %s", vpcName, vpc2Name)
		if !diffSameUID {
			header += " (note that the compared VPCs are of different UIDs)"
		}
		return header + "\n", nil
	case Explain:
		return explainHeader(explanation), nil
	}
	return "", nil // should never get here
}

func (t *TextOutputFormatter) WriteOutput(c1, c2 *VPCConfig,
	conn *VPCConnectivity,
	subnetsConn *VPCsubnetConnectivity,
	cfgsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase,
	explanation *Explanation) (*SingleAnalysisOutput, error) {
	vpc2Name := ""
	diffSameUID := true // relevant only for diff
	if c2 != nil {
		vpc2Name = c2.VPC.Name()
		diffSameUID = c1.VPC.UID() == c2.VPC.UID()
	}
	// header line - specify the VPC analyzed
	out, err := headerOfAnalyzedVPC(uc, c1.VPC.Name(), vpc2Name, c1, explanation, diffSameUID)
	if err != nil {
		return nil, err
	}
	hasStatelessConns := false

	// get output by analysis type
	switch uc {
	case AllEndpoints:
		out += conn.GroupedConnectivity.String(c1)
		hasStatelessConns = conn.GroupedConnectivity.hasStatelessConns()
	case AllSubnets:
		out += subnetsConn.GroupedConnectivity.String(c1)
		hasStatelessConns = subnetsConn.GroupedConnectivity.hasStatelessConns()
	case SingleSubnet:
		out += c1.GetConnectivityOutputPerEachSubnetSeparately()
	case SubnetsDiff, EndpointsDiff:
		out += cfgsDiff.String()
		hasStatelessConns = cfgsDiff.hasStatelessConns()
	case Explain:
		out += explanation.String(false)
	}
	// write output to file and return the output string
	_, err = WriteToFile(out, outFile)
	return &SingleAnalysisOutput{Output: out, VPC1Name: c1.VPC.Name(),
		VPC2Name: vpc2Name, format: Text, hasStatelessConn: hasStatelessConns}, err
}
