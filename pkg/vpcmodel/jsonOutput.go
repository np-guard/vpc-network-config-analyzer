package vpcmodel

import (
	"encoding/json"
	"os"
)

type JSONoutputFormatter struct {
}

type connLine struct {
	Src  Node   `json:"src"`
	Dst  Node   `json:"dst"`
	Conn string `json:"conn"`
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

func writeToFile(content, fileName string) error {
	if fileName != "" {
		return os.WriteFile(fileName, []byte(content), writeFileMde)
	}
	return nil
}

func (j *JSONoutputFormatter) WriteOutput(c *CloudConfig, conn *VPCConnectivity, outFile string) (string, error) {
	all := allInfo{}

	connLines := []connLine{}

	for src, srcMap := range conn.AllowedConnsCombined {
		for dst, conn := range srcMap {
			if conn.IsEmpty() {
				continue
			}
			connLines = append(connLines, connLine{Src: src, Dst: dst, Conn: conn.String()})
		}
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
	err = writeToFile(resStr, outFile)
	return resStr, err
}
