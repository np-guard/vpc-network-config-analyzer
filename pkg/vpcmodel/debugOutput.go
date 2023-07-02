package vpcmodel

type DebugoutputFormatter struct {
}

func (t *DebugoutputFormatter) WriteOutputVsiLevel(c *CloudConfig, conn *VPCConnectivity, outFile string, grouping bool) (string, error) {
	// TODO: add a flag of whether to include grouped output or not
	// TODO: add another 'debug' format that includes all detailed output
	out := conn.DetailedString()
	err := WriteToFile(out, outFile)
	return out, err
}

func (t *DebugoutputFormatter) WriteOutputSubnetLevel(subnetsConn *VPCsubnetConnectivity, outFile string) (string, error) {
	out := subnetsConn.String()
	return writeOutput(out, outFile)
}

func (t *DebugoutputFormatter) WriteOutputDebugSubnet(c *CloudConfig, outFile string) (string, error) {
	out := c.GetConnectivityOutputPerEachSubnetSeparately()
	return writeOutput(out, outFile)
}
