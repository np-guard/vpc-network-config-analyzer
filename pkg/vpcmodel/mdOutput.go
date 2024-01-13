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
	out, err := headerOfAnalyzedVPC(uc, c1.VPC.Name(), v2Name, c1)
	if err != nil {
		return nil, err
	}
	out = "# " + out
	lines := []string{mdDefaultTitle, mdDefaultHeader}
	var connLines []string
	switch uc {
	case AllEndpoints:
		connLines = m.getGroupedOutput(conn.GroupedConnectivity)
	case AllSubnets:
		connLines = m.getGroupedOutput(subnetsConn.GroupedConnectivity)
	case SubnetsDiff, EndpointsDiff:
		var mdTitle, mdHeader string
		if uc == EndpointsDiff {
			mdTitle = mdEndpointsDiffTitle
			mdHeader = mdEndPointsDiffHeader
		} else {
			mdTitle = mdSubnetsDiffTitle
			mdHeader = mdSubnetsDiffHeader
		}
		lines = []string{mdTitle, mdHeader}
		connLines = m.getGroupedDiffOutput(cfgsDiff)
	case SingleSubnet:
		return nil, errors.New("DebugSubnet use case not supported for md format currently ")
	}
	out += linesToOutput(connLines, lines)

	_, err = WriteToFile(out, outFile)
	return &SingleAnalysisOutput{Output: out, VPC1Name: c1.VPC.Name(), VPC2Name: v2Name, format: MD}, err
}

func linesToOutput(connLines, lines []string) string {
	sort.Strings(connLines)
	lines = append(lines, connLines...)
	out := strings.Join(lines, "\n")
	out += "\n"
	return out
}

func (m *MDoutputFormatter) getGroupedOutput(connLines *GroupConnLines) []string {
	lines := make([]string, len(connLines.GroupedLines))
	for i, line := range connLines.GroupedLines {
		lines[i] = getGroupedMDLine(line)
	}
	return lines
}

func (m *MDoutputFormatter) getGroupedDiffOutput(diff *diffBetweenCfgs) []string {
	lines := make([]string, len(diff.groupedLines))
	for i, line := range diff.groupedLines {
		diffType, endpointsDiff := diffAndEndpointsDescription(line.commonProperties.connDiff.diff,
			line.src, line.dst, line.commonProperties.connDiff.thisMinusOther)
		conn1Str, conn2Str := conn1And2Str(line.commonProperties.connDiff)
		lines[i] = fmt.Sprintf("| %s | %s | %s | %s | %s | %s |", diffType, line.src.Name(),
			line.dst.Name(), conn1Str, conn2Str, endpointsDiff)
	}
	return lines
}

// formats a connection line for md output
func connectivityLineMD(src, dst, conn string) string {
	return fmt.Sprintf("| %s | %s | %s |", src, dst, conn)
}

func getGroupedMDLine(line *groupedConnLine) string {
	return connectivityLineMD(line.src.Name(), line.dst.Name(), line.commonProperties.groupingStrKey)
}
