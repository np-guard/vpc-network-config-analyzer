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
	uc OutputUseCase,
	explanation *Explanation) (*SingleAnalysisOutput, error) {
	out, err := headerOfAnalyzedVPC(uc, c1.VPC.Name(), "", c1, explanation)
	hasStatelessConns := false
	if err != nil {
		return nil, err
	}
	switch uc {
	case AllEndpoints:
		// TODO: add a flag of whether to include grouped output or not
		// TODO: add another 'debug' format that includes all detailed output
		out = conn.DetailedString()
		hasStatelessConns = conn.GroupedConnectivity.hasStatelessConns()
	case AllSubnets:
	case SingleSubnet:
	case SubnetsDiff, EndpointsDiff:
	}
	_, err = WriteToFile(out, outFile)
	return &SingleAnalysisOutput{Output: out, VPC1Name: c1.VPC.Name(), VPC2Name: "", format: Debug, hasStatelessConn: hasStatelessConns}, err
}
