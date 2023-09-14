package vpcmodel

import (
	"encoding/json"
	"errors"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

type JSONoutputFormatter struct {
}

type connLine struct {
	Src                EndpointElem       `json:"src"`
	Dst                EndpointElem       `json:"dst"`
	Conn               common.ConnDetails `json:"conn"`
	UnidirectionalConn common.ConnDetails `json:"unidirectional_conn,omitempty"`
}

type architecture struct {
	Nodes    []map[string]string
	NodeSets []map[string]string
	Filters  []map[string]string
	Routers  []map[string]string
}

type allInfo struct {
	Arch                  architecture `json:"architecture"`
	EndpointsConnectivity []connLine   `json:"endpoints_connectivity"`
}

func getConnLines(conn *VPCConnectivity) []connLine {
	connLines := []connLine{}

	bidirectional, unidirectional := conn.SplitAllowedConnsToUnidirectionalAndBidirectional()
	for src, srcMap := range conn.AllowedConnsCombined {
		for dst, conn := range srcMap {
			if conn.IsEmpty() {
				continue
			}
			unidirectionalConn := unidirectional.getAllowedConnForPair(src, dst)
			bidirectionalConn := bidirectional.getAllowedConnForPair(src, dst)
			if !unidirectionalConn.IsEmpty() {
				connLines = append(connLines, connLine{Src: src, Dst: dst, Conn: common.ConnToJSONRep(bidirectionalConn),
					UnidirectionalConn: common.ConnToJSONRep(unidirectionalConn)})
			} else {
				connLines = append(connLines, connLine{Src: src, Dst: dst, Conn: common.ConnToJSONRep(conn)})
			}
		}
	}
	return connLines
}

func (j *JSONoutputFormatter) WriteOutputAllEndpoints(c *CloudConfig, conn *VPCConnectivity, outFile string, grouping bool) (
	string,
	error,
) {
	all := allInfo{}
	connLines := getConnLines(conn)

	all.EndpointsConnectivity = connLines

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

	return writeJSON(all, outFile)
}

func writeJSON(s interface{}, outFile string) (string, error) {
	res, err := json.MarshalIndent(s, "", "    ")
	if err != nil {
		return "", err
	}
	resStr := string(res)
	err = WriteToFile(resStr, outFile)
	return resStr, err
}

func (j *JSONoutputFormatter) WriteOutputAllSubnets(subnetsConn *VPCsubnetConnectivity, outFile string) (string, error) {
	all := allSubnetsConnectivity{}
	all.Connectivity = getConnLinesForSubnetsConnectivity(subnetsConn)
	return writeJSON(all, outFile)
}

type subnetsConnectivityConnLine struct {
	Src  VPCResourceIntf    `json:"src"`
	Dst  VPCResourceIntf    `json:"dst"`
	Conn common.ConnDetails `json:"conn"`
}

type allSubnetsConnectivity struct {
	Connectivity []subnetsConnectivityConnLine `json:"subnets_connectivity"`
}

func getConnLinesForSubnetsConnectivity(conn *VPCsubnetConnectivity) []subnetsConnectivityConnLine {
	connLines := []subnetsConnectivityConnLine{}
	for src, nodeConns := range conn.AllowedConnsCombined {
		for dst, conns := range nodeConns {
			if conns.IsEmpty() {
				continue
			}
			// currently not supported with grouping
			srcNode := conn.CloudConfig.NameToResource[src.Name()]
			dstNode := conn.CloudConfig.NameToResource[dst.Name()]
			connLines = append(connLines, subnetsConnectivityConnLine{srcNode, dstNode, common.ConnToJSONRep(conns)})
		}
	}
	return connLines
}

func (j *JSONoutputFormatter) WriteOutputSingleSubnet(c *CloudConfig, outFile string) (string, error) {
	return "", errors.New("DebugSubnet use case not supported for md format currently ")
}
