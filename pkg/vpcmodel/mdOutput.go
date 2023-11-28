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
	mdDefaultTitle        = "## Endpoint connectivity report"
	mdDefaultHeader       = "| src | dst | conn |\n|-----|-----|------|"
	mdEndpointsDiffTitle  = "## Endpoints diff report"
	mdSubnetsDiffTitle    = "## Subnets diff report"
	mdEndPointsDiffHeader = "| type | src |  dst | conn1 | conn2 | vsis-diff-info |\n" +
		"|------|-----|------|-------|-------|----------------|"
	mdSubnetsDiffHeader = "| type | src |  dst | conn1 | conn2 | subnets-diff-info |\n" +
		"|------|-----|------|-------|-------|-------------------|"
)

func (m *MDoutputFormatter) WriteOutput(c1, c2 *VPCConfig,
	conn *VPCConnectivity,
	subnetsConn *VPCsubnetConnectivity,
	cfgsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase) (*SingleAnalysisOutput, error) {
	// get output by analysis type
	v2Name := ""
	if c2 != nil {
		v2Name = c2.VPC.Name()
	}
	out := "# " + headerOfAnalyzedVPC(uc, c1.VPC.Name(), v2Name)
	switch uc {
	case AllEndpoints:
		lines := []string{mdDefaultTitle, mdDefaultHeader}
		connLines := m.getGroupedOutput(conn)
		sort.Strings(connLines)
		lines = append(lines, connLines...)
		out += strings.Join(lines, "\n")
		out += asteriskDetails
	case SubnetsDiff, EndpointsDiff:
		var mdTitle, mdHeader string
		if uc == EndpointsDiff {
			mdTitle = mdEndpointsDiffTitle
			mdHeader = mdEndPointsDiffHeader
		} else {
			mdTitle = mdSubnetsDiffTitle
			mdHeader = mdSubnetsDiffHeader
		}
		lines := []string{mdTitle, mdHeader}
		connLines := m.getGroupedDiffOutput(cfgsDiff)
		sort.Strings(connLines)
		lines = append(lines, connLines...)
		out += strings.Join(lines, "\n")
		out += asteriskDetails
	case AllSubnets:
		return nil, errors.New("SubnetLevel use case not supported for md format currently ")
	case SingleSubnet:
		return nil, errors.New("DebugSubnet use case not supported for md format currently ")
	}

	_, err := WriteToFile(out, outFile)
	return &SingleAnalysisOutput{Output: out, VPC1Name: c1.VPC.Name(), VPC2Name: v2Name, format: MD}, err
}

func (m *MDoutputFormatter) getGroupedOutput(conn *VPCConnectivity) []string {
	lines := make([]string, len(conn.GroupedConnectivity.GroupedLines))
	for i, line := range conn.GroupedConnectivity.GroupedLines {
		lines[i] = getGroupedMDLine(line)
	}
	return lines
}

func (m *MDoutputFormatter) getGroupedDiffOutput(diff *diffBetweenCfgs) []string {
	lines := make([]string, len(diff.groupedLines))
	for i, line := range diff.groupedLines {
		decodedDetails := strings.Split(line.Conn, semicolon)
		lines[i] = fmt.Sprintf("| %s | %s | %s | %s | %s | %s |", decodedDetails[0], line.Src.Name(),
			line.Dst.Name(), decodedDetails[1], decodedDetails[2], decodedDetails[3])
	}
	return lines
}

// formats a connection line for md output
func connectivityLineMD(src, dst, conn string) string {
	return fmt.Sprintf("| %s | %s | %s |", src, dst, conn)
}

func getGroupedMDLine(line *groupedConnLine) string {
	return connectivityLineMD(line.src.Name(), line.dst.Name(), line.commonProperties.connStrKey)
}
