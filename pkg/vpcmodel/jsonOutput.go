package vpcmodel

import (
	"encoding/json"
	"errors"
	"sort"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

type JSONoutputFormatter struct {
}

func (j *JSONoutputFormatter) WriteOutput(c *VPCConfig,
	conn *VPCConnectivity,
	subnetsConn *VPCsubnetConnectivity,
	outFile string,
	grouping bool,
	uc OutputUseCase) (string, error) {
	var all interface{}
	switch uc {
	case AllEndpoints:
		all = allInfo{EndpointsConnectivity: getConnLines(conn)}
	case AllSubnets:
		all = allSubnetsConnectivity{Connectivity: getConnLinesForSubnetsConnectivity(subnetsConn)}
	case SingleSubnet:
		return "", errors.New("DebugSubnet use case not supported for JSON format currently ")
	}
	return writeJSON(all, outFile)
}

type connLine struct {
	Src                EndpointElem       `json:"src"`
	Dst                EndpointElem       `json:"dst"`
	Conn               common.ConnDetails `json:"conn"`
	UnidirectionalConn common.ConnDetails `json:"unidirectional_conn,omitempty"`
}

func sortConnLines(connLines []connLine) {
	sort.Slice(connLines, func(i, j int) bool {
		if connLines[i].Src.Name() != connLines[j].Src.Name() {
			return connLines[i].Src.Name() < connLines[j].Src.Name()
		}
		return connLines[i].Dst.Name() < connLines[j].Dst.Name()
	})
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

	sortConnLines(connLines)
	return connLines
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

type allSubnetsConnectivity struct {
	Connectivity []connLine `json:"subnets_connectivity"`
}

func getConnLinesForSubnetsConnectivity(conn *VPCsubnetConnectivity) []connLine {
	connLines := []connLine{}
	for src, nodeConns := range conn.AllowedConnsCombined {
		for dst, conns := range nodeConns {
			if conns.IsEmpty() {
				continue
			}
			// currently not supported with grouping
			connLines = append(connLines, connLine{
				Src:  src,
				Dst:  dst,
				Conn: common.ConnToJSONRep(conns),
			})
		}
	}

	sortConnLines(connLines)
	return connLines
}
