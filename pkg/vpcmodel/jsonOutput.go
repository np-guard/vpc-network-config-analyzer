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

type allInfo struct {
	EndpointsConnectivity []connLine `json:"endpoints_connectivity"`
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
