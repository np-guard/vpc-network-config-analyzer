package vpcmodel

type TextOutputFormatter struct {
}

const asteriskDetails = "\n\n* connections that are limited to unidirectional flow only\n"

func (t *TextOutputFormatter) WriteOutputAllEndpoints(c *CloudConfig, conn *VPCConnectivity, outFile string, grouping bool) (
	string,
	error,
) {
	// TODO: add a flag of whether to include grouped output or not
	// TODO: add another 'debug' format that includes all detailed output
	var out string
	if grouping {
		out = groupedConnectivityString(conn)
	} else {
		out = conn.String()
		out += asteriskDetails
	}
	return writeOutput(out, outFile)
}

func (t *TextOutputFormatter) WriteOutputAllSubnets(subnetsConn *VPCsubnetConnectivity, outFile string) (string, error) {
	out := subnetsConn.String()
	return writeOutput(out, outFile)
}

func (t *TextOutputFormatter) WriteOutputSingleSubnet(c *CloudConfig, outFile string) (string, error) {
	out := c.GetConnectivityOutputPerEachSubnetSeparately()
	return writeOutput(out, outFile)
}

func groupedConnectivityString(conn *VPCConnectivity) string {
	return "\ngrouped output:\n" + conn.GroupedConnectivity.String()
}
