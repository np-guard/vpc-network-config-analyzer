package vpcmodel

type TextOutputFormatter struct {
}

const asteriskDetails = "\n\nconnections are stateful unless marked with *\n"

func (t *TextOutputFormatter) WriteOutputAllEndpoints(c *CloudConfig, conn *VPCConnectivity, outFile string, grouping bool) (
	string,
	error,
) {
	var out string
	if grouping {
		out = groupedConnectivityString(conn)
	} else {
		out = conn.String()
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
