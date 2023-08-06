package vpcmodel

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type MDoutputFormatter struct {
}

const (
	mdTitle  = "## Endpoint connectivity report"
	mdHeader = "| src | dst | conn |\n|-----|-----|------|"
)

func (m *MDoutputFormatter) WriteOutputAllEndpoints(c *CloudConfig, conn *VPCConnectivity, outFile string, grouping bool) (string, error) {
	lines := []string{mdTitle, mdHeader}
	var connLines []string
	connLines = m.getGroupedOutput(conn)

	sort.Strings(connLines)
	lines = append(lines, connLines...)
	out := strings.Join(lines, "\n")
	out += asteriskDetails
	err := WriteToFile(out, outFile)
	return out, err
}

func (m *MDoutputFormatter) WriteOutputAllSubnets(subnetsConn *VPCsubnetConnectivity, outFile string) (string, error) {
	return "", errors.New("SubnetLevel use case not supported for md format currently ")
}

func (m *MDoutputFormatter) WriteOutputSingleSubnet(c *CloudConfig, outFile string) (string, error) {
	return "", errors.New("DebugSubnet use case not supported for md format currently ")
}

func (m *MDoutputFormatter) getGroupedOutput(conn *VPCConnectivity) []string {
	lines := make([]string, len(conn.GroupedConnectivity.GroupedLines))
	for i, line := range conn.GroupedConnectivity.GroupedLines {
		lines[i] = getGroupedMDLine(line)
	}
	return lines
}

// formats a connection line for md output
func connectivityLineMD(src, dst, conn string) string {
	return fmt.Sprintf("| %s | %s | %s |", src, dst, conn)
}

func getGroupedMDLine(line *GroupedConnLine) string {
	return connectivityLineMD(line.Src.Name(), line.Dst.Name(), line.Conn)
}
