package vpcmodel

type DebugOutputFormatter struct {
}

func (t *DebugOutputFormatter) WriteOutputAllEndpoints(c *CloudConfig, conn *VPCConnectivity, outFile string, grouping bool) (
	string,
	error,
) {
	// TODO: add a flag of whether to include grouped output or not
	// TODO: add another 'debug' format that includes all detailed output
	out := conn.DetailedString()
	err := WriteToFile(out, outFile)
	return out, err
}

func (t *DebugOutputFormatter) WriteOutputAllSubnets(subnetsConn *VPCsubnetConnectivity, outFile string) (string, error) {
	out := subnetsConn.String()
	return writeOutput(out, outFile)
}

func (t *DebugOutputFormatter) WriteOutputSingleSubnet(c *CloudConfig, outFile string) (string, error) {
	out := c.GetConnectivityOutputPerEachSubnetSeparately()
	return writeOutput(out, outFile)
}
