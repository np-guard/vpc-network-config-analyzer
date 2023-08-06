package vpcmodel

import (
	"errors"
	"fmt"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
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
	var addAsteriskDetails bool
	var connLines []string
	if grouping {
		connLines, addAsteriskDetails = m.getGroupedOutput(conn)
	} else {
		connLines, addAsteriskDetails = m.getNonGroupedOutput(conn)
	}
	sort.Strings(connLines)
	lines = append(lines, connLines...)
	out := strings.Join(lines, "\n")
	if addAsteriskDetails {
		out += asteriskDetails
	}
	err := WriteToFile(out, outFile)
	return out, err
}

func (m *MDoutputFormatter) WriteOutputAllSubnets(subnetsConn *VPCsubnetConnectivity, outFile string) (string, error) {
	return "", errors.New("SubnetLevel use case not supported for md format currently ")
}

func (m *MDoutputFormatter) WriteOutputSingleSubnet(c *CloudConfig, outFile string) (string, error) {
	return "", errors.New("DebugSubnet use case not supported for md format currently ")
}

func (m *MDoutputFormatter) getNonGroupedOutput(conn *VPCConnectivity) ([]string, bool) {
	var addAsteriskDetails bool
	lines := []string{}
	for src, srcMap := range conn.AllowedConnsCombined {
		for dst, conn := range srcMap {
			if conn.IsEmpty() {
				continue
			}
			connsStr, notStateful := conn.EnhancedString()
			connLineObj := connLine{Src: src, Dst: dst, Conn: connsStr}
			lines = append(lines, getMDLine(connLineObj))
			if notStateful {
				addAsteriskDetails = true
			}
		}
	}
	return lines, addAsteriskDetails
}

func (m *MDoutputFormatter) getGroupedOutput(conn *VPCConnectivity) ([]string, bool) {
	var addAsteriskDetails bool
	lines := make([]string, len(conn.GroupedConnectivity.GroupedLines))
	for i, line := range conn.GroupedConnectivity.GroupedLines {
		var notStateful bool
		lines[i], notStateful = getGroupedMDLine(line)
		if notStateful {
			addAsteriskDetails = true
		}
	}
	return lines, addAsteriskDetails
}

// formats a connection line for md output
func connectivityLineMD(src, dst, conn string) string {
	return fmt.Sprintf("| %s | %s | %s |", src, dst, conn)
}

func getMDLine(line connLine) string {
	return connectivityLineMD(line.Src.Name(), line.Dst.Name(), line.Conn)
}

func getGroupedMDLine(line *GroupedConnLine) (string, bool) {
	if line.IsStateful == common.StatefulFalse {
		return connectivityLineMD(line.Src.Name(), line.Dst.Name(), line.Conn+" *"), true
	}
	return connectivityLineMD(line.Src.Name(), line.Dst.Name(), line.Conn), false
}
