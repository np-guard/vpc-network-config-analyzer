package vpcmodel

import (
	"fmt"
	"strings"
)

type MDoutputFormatter struct {
}

const (
	mdTitle  = "## Endpoint connectivity report"
	mdHeader = "| src | dst | conn |\n|-----|-----|------|"
)

// formats a connection line for md output
func getMDLine(c connLine) string {
	return fmt.Sprintf("| %s | %s | %s |", c.Src.Name(), c.Dst.Name(), c.Conn)
}

func (m *MDoutputFormatter) WriteOutput(c *CloudConfig, conn *VPCConnectivity, outFile string) (string, error) {
	lines := []string{mdTitle, mdHeader}

	for src, srcMap := range conn.AllowedConnsCombined {
		for dst, conn := range srcMap {
			if conn.IsEmpty() {
				continue
			}
			connLineObj := connLine{Src: src, Dst: dst, Conn: conn.String()}
			lines = append(lines, getMDLine(connLineObj))
		}
	}

	out := strings.Join(lines, "\n")
	err := WriteToFile(out, outFile)
	return out, err
}
