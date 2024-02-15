package vpcmodel

import (
	"errors"
	"fmt"
	"strings"
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

func headerOfAnalyzedVPC(uc OutputUseCase, vpcName, vpc2Name string, c1 *VPCConfig, explanation *Explanation) (string, error) {
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
		return fmt.Sprintf("Connectivity diff between VPC %s and VPC %s\n", vpcName, vpc2Name), nil
	case Explain:
		connStr := ""
		if explanation.connQuery != nil {
			connStr = " for " + explanation.connQuery.String()
		}
		srcNetworkInterfaces := explainNetworkInterfaces(explanation.srcNetworkInterfacesFromIP)
		dstNetworkInterfaces := explainNetworkInterfaces(explanation.dstNetworkInterfacesFromIP)
		header1 := fmt.Sprintf("Connectivity explanation%s between %s%s and %s%s",
			connStr, explanation.src, srcNetworkInterfaces, explanation.dst, dstNetworkInterfaces)
		header2 := strings.Repeat("=", len(header1))
		return header1 + "\n" + header2 + "\n\n", nil
	}
	return "", nil // should never get here
}

// in case the src/dst of a network interface given as an internal address connected to network interface
func explainNetworkInterfaces(nodes []Node) string {
	if len(nodes) == 0 {
		return ""
	}
	networkinterfaces := make([]string, len(nodes))
	for i, node := range nodes {
		networkinterfaces[i] = node.Name()
	}
	return leftParentheses + strings.Join(networkinterfaces, ", ") + rightParentheses
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
	if c2 != nil {
		vpc2Name = c2.VPC.Name()
	}
	// header line - specify the VPC analyzed
	out, err := headerOfAnalyzedVPC(uc, c1.VPC.Name(), vpc2Name, c1, explanation)
	if err != nil {
		return nil, err
	}
	hasStatelessConns := false

	// get output by analysis type
	switch uc {
	case AllEndpoints:
		out += conn.GroupedConnectivity.String()
		hasStatelessConns = conn.GroupedConnectivity.hasStatelessConns()
	case AllSubnets:
		out += subnetsConn.GroupedConnectivity.String()
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
