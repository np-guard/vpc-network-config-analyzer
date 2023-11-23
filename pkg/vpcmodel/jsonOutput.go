package vpcmodel

import (
	"encoding/json"
	"errors"
	"sort"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

type JSONoutputFormatter struct {
}

const connectionChanged = "connection changed"

func (j *JSONoutputFormatter) WriteOutput(c1, c2 *VPCConfig,
	conn *VPCConnectivity,
	subnetsConn *VPCsubnetConnectivity,
	cfgsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase) (*SingleAnalysisOutput, error) {
	var all interface{}
	switch uc {
	case AllEndpoints:
		all = allInfo{EndpointsConnectivity: getConnLines(conn)}
	case AllSubnets:
		all = allSubnetsConnectivity{Connectivity: getConnLinesForSubnetsConnectivity(subnetsConn)}
	case SubnetsDiff, EndpointsDiff:
		all = allSemanticDiff{SemanticDiff: getDiffLines(cfgsDiff)}
	case SingleSubnet:
		return nil, errors.New("DebugSubnet use case not supported for JSON format currently ")
	}
	outStr, err := writeJSON(all, outFile)
	v2Name := ""
	if c2 != nil {
		v2Name = c2.VPC.Name()
	}
	return &SingleAnalysisOutput{Output: outStr, VPC1Name: c1.VPC.Name(), VPC2Name: v2Name, format: JSON, jsonStruct: all}, err
}

type connLine struct {
	Src                EndpointElem       `json:"src"`
	Dst                EndpointElem       `json:"dst"`
	Conn               common.ConnDetails `json:"conn"`
	UnidirectionalConn common.ConnDetails `json:"unidirectional_conn,omitempty"`
}

type diffLine struct {
	Diff  string             `json:"diff-type"`
	Src   EndpointElem       `json:"src"`
	Dst   EndpointElem       `json:"dst"`
	Conn1 common.ConnDetails `json:"conn1"`
	Conn2 common.ConnDetails `json:"conn2"`
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
	_, err = WriteToFile(resStr, outFile)
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

type allSemanticDiff struct {
	SemanticDiff []diffLine `json:"semantic_diff"`
}

func getDiffLines(configsDiff *diffBetweenCfgs) []diffLine {
	diffLines := getDirectionalDiffLines(configsDiff.cfg1ConnRemovedFrom2, true)
	diffLines = append(diffLines, getDirectionalDiffLines(configsDiff.cfg2ConnRemovedFrom1, false)...)
	return diffLines
}

func getDirectionalDiffLines(connectDiff connectivityDiff, thisMinusTheOther bool) []diffLine {
	diffLines := []diffLine{}
	for src, endpointConnDiff := range connectDiff {
		for dst, connDiff := range endpointConnDiff {
			var diffStr string
			if thisMinusTheOther {
				diffStr = getDiffStrThis(connDiff.diff)
			} else {
				diffStr = getDiffStrOther(connDiff.diff)
			}
			diffLines = append(diffLines, diffLine{diffStr, src, dst, common.ConnToJSONRep(connDiff.conn1), common.ConnToJSONRep(connDiff.conn2)})
		}
	}

	sortDiffLines(diffLines)
	return diffLines
}

func sortDiffLines(diffLines []diffLine) {
	sort.Slice(diffLines, func(i, j int) bool {
		if diffLines[i].Diff != diffLines[j].Diff {
			return diffLines[i].Diff < diffLines[j].Diff
		}
		if diffLines[i].Src.Name() != diffLines[j].Src.Name() {
			return diffLines[i].Src.Name() < diffLines[j].Src.Name()
		}
		return diffLines[i].Dst.Name() < diffLines[j].Dst.Name()
	})
}

func getDiffStrThis(diff DiffType) string {
	switch diff {
	case missingSrcEP:
		return "source removed"
	case missingDstEP:
		return "destination removed"
	case missingSrcDstEP:
		return "source and destination removed"
	case missingConnection:
		return "connection removed"
	case changedConnection:
		return connectionChanged
	}
	return ""
}

func getDiffStrOther(diff DiffType) string {
	switch diff {
	case missingSrcEP:
		return "source added"
	case missingDstEP:
		return "destination added"
	case missingSrcDstEP:
		return "source and destination added"
	case missingConnection:
		return "connection added"
	case changedConnection:
		return connectionChanged
	}
	return ""
}
