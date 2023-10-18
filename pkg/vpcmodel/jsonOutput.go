package vpcmodel

import (
	"encoding/json"
	"errors"
	"sort"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

type JSONoutputFormatter struct {
}

type connLine struct {
	Src                EndpointElem       `json:"src"`
	Dst                EndpointElem       `json:"dst"`
	Conn               common.ConnDetails `json:"conn"`
	UnidirectionalConn common.ConnDetails `json:"unidirectional_conn,omitempty"`
	connStr            string             // connStr used for sorting
}

func sortConnLines(connLines []connLine) {
	sort.Slice(connLines, func(i, j int) bool {
		if connLines[i].Src.Name() != connLines[j].Src.Name() {
			return connLines[i].Src.Name() < connLines[j].Src.Name()
		}
		if connLines[i].Dst.Name() != connLines[j].Dst.Name() {
			return connLines[i].Dst.Name() < connLines[j].Dst.Name()
		}

		return connLines[i].connStr < connLines[j].connStr
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
					UnidirectionalConn: common.ConnToJSONRep(unidirectionalConn), connStr: bidirectionalConn.String()})
			} else {
				connLines = append(connLines, connLine{Src: src, Dst: dst, Conn: common.ConnToJSONRep(conn), connStr: conn.String()})
			}
		}
	}

	sortConnLines(connLines)
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
				Src:     src,
				Dst:     dst,
				Conn:    common.ConnToJSONRep(conns),
				connStr: conns.String(),
			})
		}
	}

	sortConnLines(connLines)
	return connLines
}

func (j *JSONoutputFormatter) WriteOutputSingleSubnet(c *CloudConfig, outFile string) (string, error) {
	return "", errors.New("DebugSubnet use case not supported for md format currently ")
}
