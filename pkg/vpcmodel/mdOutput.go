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

func (m *MDoutputFormatter) WriteOutput(c *VPCConfig,
	conn *VPCConnectivity,
	subnetsConn *VPCsubnetConnectivity,
	outFile string,
	grouping bool,
	uc OutputUseCase) (string, error) {
	// get output by analysis type
	out := "# " + headerOfAnalyzedVPC(c.VPCName)
	switch uc {
	case AllEndpoints:
		lines := []string{mdTitle, mdHeader}
		connLines := m.getGroupedOutput(conn)
		sort.Strings(connLines)
		lines = append(lines, connLines...)
		out += strings.Join(lines, "\n")
		out += asteriskDetails
	case AllSubnets:
		return "", errors.New("SubnetLevel use case not supported for md format currently ")
	case SingleSubnet:
		return "", errors.New("DebugSubnet use case not supported for md format currently ")
	}

	err := WriteToFile(out, outFile)
	return out, err
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
