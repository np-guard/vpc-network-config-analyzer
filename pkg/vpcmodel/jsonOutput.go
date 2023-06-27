package vpcmodel

import (
	"encoding/json"
	"errors"
	"os"
)

type JSONoutputFormatter struct {
}

type connLine struct {
	Src  EndpointElem `json:"src"`
	Dst  EndpointElem `json:"dst"`
	Conn string       `json:"conn"`
}

type architecture struct {
	Nodes    []map[string]string
	NodeSets []map[string]string
	Filters  []map[string]string
	Routers  []map[string]string
}

type allInfo struct {
	Arch         architecture `json:"architecture"`
	Connectivity []connLine   `json:"connectivity"`
}

func WriteToFile(content, fileName string) error {
	if fileName != "" {
		return os.WriteFile(fileName, []byte(content), writeFileMde)
	}
	return nil
}

func getConnLines(conn *VPCConnectivity) []connLine {
	connLines := []connLine{}

	for src, srcMap := range conn.AllowedConnsCombined {
		for dst, conn := range srcMap {
			if conn.IsEmpty() {
				continue
			}
			connLines = append(connLines, connLine{Src: src, Dst: dst, Conn: conn.String()})
		}
	}
	return connLines
}

func getGroupedConnLines(conn *VPCConnectivity) []connLine {
	connLines := make([]connLine, len(conn.GroupedConnectivity.GroupedLines))
	for i, line := range conn.GroupedConnectivity.GroupedLines {
		connLines[i] = connLine{line.Src, line.Dst, string(line.Conn)}
	}
	return connLines
}

func (j *JSONoutputFormatter) WriteOutputVsiLevel(c *CloudConfig, conn *VPCConnectivity, outFile string, grouping bool) (string, error) {
	all := allInfo{}
	var connLines []connLine
	if grouping {
		connLines = getGroupedConnLines(conn)
	} else {
		connLines = getConnLines(conn)
	}

	all.Connectivity = connLines

	all.Arch = architecture{
		Nodes:    []map[string]string{},
		NodeSets: []map[string]string{},
		Filters:  []map[string]string{},
		Routers:  []map[string]string{},
	}
	for _, n := range c.Nodes {
		all.Arch.Nodes = append(all.Arch.Nodes, n.DetailsMap())
	}
	for _, n := range c.NodeSets {
		all.Arch.NodeSets = append(all.Arch.NodeSets, n.DetailsMap())
	}
	for _, fl := range c.FilterResources {
		all.Arch.Filters = append(all.Arch.Filters, fl.DetailsMap()...)
	}
	for _, r := range c.RoutingResources {
		all.Arch.Routers = append(all.Arch.Routers, r.DetailsMap())
	}

	res, err := json.MarshalIndent(all, "", "    ")
	if err != nil {
		return "", err
	}
	resStr := string(res)
	err = WriteToFile(resStr, outFile)
	return resStr, err
}

func (j *JSONoutputFormatter) WriteOutputSubnetLevel(subnetsConn *VPCsubnetConnectivity, outFile string) (string, error) {
	return "", errors.New("SubnetLevel use case not supported for md format currently ")
}

func (j *JSONoutputFormatter) WriteOutputDebugSubnet(c *CloudConfig, outFile string) (string, error) {
	return "", errors.New("DebugSubnet use case not supported for md format currently ")
}
