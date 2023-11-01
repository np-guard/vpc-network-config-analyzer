package vpcmodel

import "fmt"

type TextOutputFormatter struct {
}

const asteriskDetails = "\n\nconnections are stateful unless marked with *\n"

func headerOfAnalyzedVPC(vpcName string) string {
	return fmt.Sprintf("Analysis for VPC %s\n", vpcName)
}

func (t *TextOutputFormatter) WriteOutput(c *VPCConfig,
	conn *VPCConnectivity,
	subnetsConn *VPCsubnetConnectivity,
	outFile string,
	grouping bool,
	uc OutputUseCase) (*VPCAnalysisOutput, error) {
	// header line - specify the VPC analyzed
	out := headerOfAnalyzedVPC(c.VPC.Name())
	// get output by analysis type
	switch uc {
	case AllEndpoints:
		out += conn.GroupedConnectivity.String()
	case AllSubnets:
		out += subnetsConn.String()
	case SingleSubnet:
		out += c.GetConnectivityOutputPerEachSubnetSeparately()
	}
	// write output to file and return the output string
	outStr, err := WriteToFile(out, outFile)
	return &VPCAnalysisOutput{Output: outStr, VPCName: c.VPC.Name(), format: Text}, err
}
