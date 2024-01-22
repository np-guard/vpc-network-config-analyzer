package vpcmodel

import (
	"encoding/json"
	"errors"
	"sort"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

type JSONoutputFormatter struct {
}

func (j *JSONoutputFormatter) WriteOutput(c1, c2 *VPCConfig,
	conn *VPCConnectivity,
	subnetsConn *VPCsubnetConnectivity,
	cfgsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase,
	explanation *Explanation) (*SingleAnalysisOutput, error) {
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
	SrcChange string             `json:"src-change"`
	DstChange string             `json:"dst-change"`
	Src       EndpointElem       `json:"src"`
	Dst       EndpointElem       `json:"dst"`
	Conn1     common.ConnDetails `json:"conn1"`
	Conn2     common.ConnDetails `json:"conn2"`
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
	diffLines := getDirectionalDiffLines(configsDiff.cfg1ConnRemovedFrom2)
	diffLines = append(diffLines, getDirectionalDiffLines(configsDiff.cfg2ConnRemovedFrom1)...)
	return diffLines
}

func sortDiffLines(diffLines []diffLine) {
	sort.Slice(diffLines, func(i, j int) bool {
		if diffLines[i].SrcChange != diffLines[j].SrcChange {
			return diffLines[i].SrcChange < diffLines[j].SrcChange
		}
		if diffLines[i].DstChange != diffLines[j].DstChange {
			return diffLines[i].DstChange < diffLines[j].DstChange
		}
		if diffLines[i].Src.Name() != diffLines[j].Src.Name() {
			return diffLines[i].Src.Name() < diffLines[j].Src.Name()
		}
		return diffLines[i].Dst.Name() < diffLines[j].Dst.Name()
	})
}

func getDirectionalDiffLines(connectDiff connectivityDiff) []diffLine {
	diffLines := []diffLine{}
	for src, endpointConnDiff := range connectDiff {
		for dst, connDiff := range endpointConnDiff {
			var diffSrcStr, diffDstStr string
			if connDiff.thisMinusOther {
				diffSrcStr = getDiffSrcThis(connDiff.diff)
				diffDstStr = getDiffDstThis(connDiff.diff)
			} else {
				diffSrcStr = getDiffSrcOther(connDiff.diff)
				diffDstStr = getDiffDstOther(connDiff.diff)
			}
			diffLines = append(diffLines, diffLine{diffSrcStr, diffDstStr,
				src, dst, common.ConnToJSONRep(connDiff.conn1), common.ConnToJSONRep(connDiff.conn2)})
		}
	}

	sortDiffLines(diffLines)
	return diffLines
}

const (
	removed = "removed"
	added   = "added"
	none    = "none"
)

func getDiffSrcThis(diff DiffType) string {
	if diff == missingSrcDstEP || diff == missingSrcEP {
		return removed
	}
	return none
}

func getDiffSrcOther(diff DiffType) string {
	if diff == missingSrcDstEP || diff == missingSrcEP {
		return added
	}
	return none
}

func getDiffDstThis(diff DiffType) string {
	if diff == missingSrcDstEP || diff == missingSrcEP {
		return removed
	}
	return none
}

func getDiffDstOther(diff DiffType) string {
	if diff == missingSrcDstEP || diff == missingDstEP {
		return added
	}
	return none
}
