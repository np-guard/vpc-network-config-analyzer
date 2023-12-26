package vpcmodel

import (
	"errors"
	"fmt"
)

type TextOutputFormatter struct {
}

func headerOfAnalyzedVPC(uc OutputUseCase, vpcName, vpc2Name string, c1 *VPCConfig) (string, error) {
	switch uc {
	case AllEndpoints, AllSubnets, SingleSubnet:
		if c1.IsMultipleVPCsConfig {
			if len(c1.RoutingResources) != 1 {
				return "", errors.New("unexpected config of multiple VPCs connected by TGW, missing TGW resource")
			}
			tgw := c1.RoutingResources[0]
			return fmt.Sprintf("Connectivity between VPCs connected by TGW %s (UID: %s)\n", tgw.Name(), tgw.UID()), nil
		}
		return fmt.Sprintf("Connectivity for VPC %s\n", vpcName), nil
	case SubnetsDiff, EndpointsDiff:
		return fmt.Sprintf("Connectivity diff between VPC %s and VPC %s\n", vpcName, vpc2Name), nil
	}
	return "", nil // should never get here
}

func (t *TextOutputFormatter) WriteOutput(c1, c2 *VPCConfig,
	conn *VPCConnectivity,
	subnetsConn *VPCsubnetConnectivity,
	cfgsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase) (*SingleAnalysisOutput, error) {
	vpc2Name := ""
	if c2 != nil {
		vpc2Name = c2.VPC.Name()
	}
	// header line - specify the VPC analyzed
	out, err := headerOfAnalyzedVPC(uc, c1.VPC.Name(), vpc2Name, c1)
	if err != nil {
		return nil, err
	}
	unStateFul := false

	// get output by analysis type
	switch uc {
	case AllEndpoints:
		out += conn.GroupedConnectivity.String()
		unStateFul = conn.GroupedConnectivity.HasStatelessConns()
	case AllSubnets:
		out += subnetsConn.String()
		unStateFul = subnetsConn.GroupedConnectivity.HasStatelessConns()
	case SingleSubnet:
		out += c1.GetConnectivityOutputPerEachSubnetSeparately()
	case SubnetsDiff, EndpointsDiff:
		out += cfgsDiff.String()
		unStateFul = cfgsDiff.HasStatelessConns()
	}
	// write output to file and return the output string
	_, err = WriteToFile(out, outFile)
	return &SingleAnalysisOutput{Output: out, VPC1Name: c1.VPC.Name(), VPC2Name: vpc2Name, format: Text, HaveUnStateFulConn: unStateFul}, err
}
