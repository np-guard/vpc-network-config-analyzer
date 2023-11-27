package vpcmodel

type DebugOutputFormatter struct {
}

func (t *DebugOutputFormatter) WriteOutput(c1, c2 *VPCConfig,
	conn *VPCConnectivity,
	subnetsConn *VPCsubnetConnectivity,
	subnetsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase) (*VPCAnalysisOutput, error) {
	out := headerOfAnalyzedVPC(c1.VPC.Name(), "")
	switch uc {
	case AllEndpoints:
		// TODO: add a flag of whether to include grouped output or not
		// TODO: add another 'debug' format that includes all detailed output
		out = conn.DetailedString()
	case AllSubnets:
		out = subnetsConn.String()
	case SingleSubnet:
		out = c1.GetConnectivityOutputPerEachSubnetSeparately()
	}
	_, err := WriteToFile(out, outFile)
	return &VPCAnalysisOutput{Output: out, VPCName: c1.VPC.Name(), format: Debug}, err
}
