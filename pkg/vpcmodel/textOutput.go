package vpcmodel

type TextOutputFormatter struct {
}

const asteriskDetails = "\n\n* Unidirectional connection\n"

func (t *TextOutputFormatter) WriteOutputAllEndpoints(c *CloudConfig, conn *VPCConnectivity, outFile string, grouping bool) (
	string,
	error,
) {
	var out string
	if grouping {
		out = "\ngrouped output:\n"
	}
	out += groupedConnectivityString(conn)
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
	return conn.GroupedConnectivity.String()
}
