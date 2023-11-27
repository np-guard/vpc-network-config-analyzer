package vpcmodel

type DebugOutputFormatter struct {
}

// WriteOutput at the moment only AllEndpoints supported for Debug mode
func (t *DebugOutputFormatter) WriteOutput(c1, c2 *VPCConfig,
	conn *VPCConnectivity,
	subnetsConn *VPCsubnetConnectivity,
	cfgsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase) (*SingleAnalysisOutput, error) {
	out := headerOfAnalyzedVPC(uc, c1.VPC.Name(), "")
	switch uc {
	case AllEndpoints:
		// TODO: add a flag of whether to include grouped output or not
		// TODO: add another 'debug' format that includes all detailed output
		out = conn.DetailedString()
	case AllSubnets:
	case SingleSubnet:
	case SubnetsDiff, EndpointsDiff:
	}
	_, err := WriteToFile(out, outFile)
	v2Name := ""
	if c2 != nil {
		v2Name = c2.VPC.Name()
	}
	return &SingleAnalysisOutput{Output: out, VPC1Name: c1.VPC.Name(), VPC2Name: v2Name, format: Debug}, err
}
