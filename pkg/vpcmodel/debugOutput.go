package vpcmodel

type DebugOutputFormatter struct {
}

func (t *DebugOutputFormatter) WriteOutput(c *VPCConfig,
	conn *VPCConnectivity,
	subnetsConn *VPCsubnetConnectivity,
	outFile string,
	grouping bool,
	uc OutputUseCase) (*VPCAnalysisOutput, error) {
	out := headerOfAnalyzedVPC(c.VPC.Name())
	switch uc {
	case AllEndpoints:
		// TODO: add a flag of whether to include grouped output or not
		// TODO: add another 'debug' format that includes all detailed output
		out = conn.DetailedString()
	case AllSubnets:
		out = subnetsConn.String()
	case SingleSubnet:
		out = c.GetConnectivityOutputPerEachSubnetSeparately()
	}
	outStr, err := WriteToFile(out, outFile)
	return &VPCAnalysisOutput{Output: outStr, VPCName: c.VPC.Name(), format: Debug}, err
}
