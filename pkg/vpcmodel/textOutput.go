package vpcmodel

import "fmt"

type TextOutputFormatter struct {
}

const asteriskDetails = "\n\nconnections are stateful unless marked with *\n"

func headerOfAnalyzedVPC(vpcName, vpc2Name string) string {
	if vpc2Name == "" {
		return fmt.Sprintf("Analysis for VPC %s\n", vpcName)
	}
	// 2nd cfg given - the analysis is a semantic diff and concerns a single cfg
	return fmt.Sprintf("Analysis for diff between VPC %s and VPC %s\n", vpcName, vpc2Name)
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
	out := headerOfAnalyzedVPC(c1.VPC.Name(), vpc2Name)
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
	v2Name := ""
	if c2 != nil {
		v2Name = c2.VPC.Name()
	}
	return &SingleAnalysisOutput{Output: out, VPC1Name: c1.VPC.Name(), VPC2Name: v2Name, format: Text}, err
}
