package vpcmodel

type DebugOutputFormatter struct {
}

func (t *DebugOutputFormatter) WriteOutput(c *VPCConfig,
	conn *VPCConnectivity,
	subnetsConn *VPCsubnetConnectivity,
	outFile string,
	grouping bool,
	uc OutputUseCase) (string, error) {
	out := headerOfAnalyzedVPC(c.VPCName)
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
	return writeOutput(out, outFile)
}
