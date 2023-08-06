package vpcmodel

import (
	"encoding/json"
	"errors"
)

type JSONoutputFormatter struct {
}

type connLine struct {
	Src                EndpointElem `json:"src"`
	Dst                EndpointElem `json:"dst"`
	Conn               string       `json:"conn"`
	UnidirectionalConn string       `json:"unidirectional_conn,omitempty"`
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

func getGroupedConnLines(conn *VPCConnectivity) []connLine {
	connLines := make([]connLine, len(conn.GroupedConnectivity.GroupedLines))
	for i, line := range conn.GroupedConnectivity.GroupedLines {
		connLines[i] = connLine{Src: line.Src, Dst: line.Dst, Conn: line.Conn}
	}
	return connLines
}

func (j *JSONoutputFormatter) WriteOutputAllEndpoints(c *CloudConfig, conn *VPCConnectivity, outFile string, grouping bool) (
	string,
	error,
) {
	all := allInfo{}
	var connLines []connLine
	connLines = getGroupedConnLines(conn)

	all.Connectivity = connLines

	all.Arch = architecture{
		Nodes:    []map[string]string{},
		NodeSets: []map[string]string{},
		Filters:  []map[string]string{},
		Routers:  []map[string]string{},
	}
	for _, n := range c.Nodes {
		all.Arch.Nodes = append(all.Arch.Nodes, n.DetailsMap()...)
	}
	for _, n := range c.NodeSets {
		all.Arch.NodeSets = append(all.Arch.NodeSets, n.DetailsMap()...)
	}
	for _, fl := range c.FilterResources {
		all.Arch.Filters = append(all.Arch.Filters, fl.DetailsMap()...)
	}
	for _, r := range c.RoutingResources {
		all.Arch.Routers = append(all.Arch.Routers, r.DetailsMap()...)
	}

	res, err := json.MarshalIndent(all, "", "    ")
	if err != nil {
		return "", err
	}
	resStr := string(res)
	err = WriteToFile(resStr, outFile)
	return resStr, err
}

func (j *JSONoutputFormatter) WriteOutputAllSubnets(subnetsConn *VPCsubnetConnectivity, outFile string) (string, error) {
	return "", errors.New("SubnetLevel use case not supported for md format currently ")
}

func (j *JSONoutputFormatter) WriteOutputSingleSubnet(c *CloudConfig, outFile string) (string, error) {
	return "", errors.New("DebugSubnet use case not supported for md format currently ")
}
