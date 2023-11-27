package vpcmodel

import "fmt"

type TextOutputFormatter struct {
}

const asteriskDetails = "\n\nconnections are stateful unless marked with *\n"

func headerOfAnalyzedVPC(uc OutputUseCase, vpcName, vpc2Name string) string {
	switch uc {
	case AllEndpoints, AllSubnets, SingleSubnet:
		return fmt.Sprintf("Analysis for VPC %s\n", vpcName)
	case SubnetsDiff, EndpointsDiff:
		return fmt.Sprintf("Diff between VPC %s and VPC %s\n", vpcName, vpc2Name)
	}
	return "" // should never get here
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
	out := headerOfAnalyzedVPC(uc, c1.VPC.Name(), vpc2Name)
	// get output by analysis type
	switch uc {
	case AllEndpoints:
		out += conn.GroupedConnectivity.String()
	case AllSubnets:
		out += subnetsConn.String()
	case SingleSubnet:
		out += c1.GetConnectivityOutputPerEachSubnetSeparately()
	case SubnetsDiff, EndpointsDiff:
		out += cfgsDiff.String()
	}
	// write output to file and return the output string
	_, err := WriteToFile(out, outFile)
	return &SingleAnalysisOutput{Output: out, VPC1Name: c1.VPC.Name(), VPC2Name: vpc2Name, format: Text}, err
}
