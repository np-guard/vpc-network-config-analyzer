package vpcmodel

type TextoutputFormatter struct {
}

func (t *TextoutputFormatter) WriteOutputVsiLevel(c *CloudConfig, conn *VPCConnectivity, outFile string, grouping bool) (string, error) {
	// TODO: add a flag of whether to include grouped output or not
	// TODO: add another 'debug' format that includes all detailed output
	var out string
	if grouping {
		out = conn.GroupedConnectivityString()
	} else {
		out = conn.String()
	}
	return writeOutput(out, outFile)
}

func (t *TextoutputFormatter) WriteOutputSubnetLevel(subnetsConn *VPCsubnetConnectivity, outFile string) (string, error) {
	out := subnetsConn.String()
	return writeOutput(out, outFile)
}

func (t *TextoutputFormatter) WriteOutputDebugSubnet(c *CloudConfig, outFile string) (string, error) {
	out := c.GetConnectivityOutputPerEachSubnetSeparately()
	return writeOutput(out, outFile)
}

func writeOutput(out, file string) (string, error) {
	err := WriteToFile(out, file)
	return out, err
}
