/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"encoding/json"
	"errors"
	"sort"

	"github.com/np-guard/models/pkg/netset"
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
	explanation *Explanation, detailExplain bool) (*SingleAnalysisOutput, error) {
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
	Src                EndpointElem   `json:"src"`
	Dst                EndpointElem   `json:"dst"`
	Conn               netset.Details `json:"conn"`
	UnidirectionalConn netset.Details `json:"unidirectional_conn,omitempty"`
}

type diffLine struct {
	SrcChange           string         `json:"src_change"`
	DstChange           string         `json:"dst_change"`
	Src                 EndpointElem   `json:"src"`
	Dst                 EndpointElem   `json:"dst"`
	Conn1               netset.Details `json:"conn1"`
	UnidirectionalConn1 netset.Details `json:"unidirectional_conn1"`
	Conn2               netset.Details `json:"conn2"`
	UnidirectionalConn2 netset.Details `json:"unidirectional_conn2"`
}

func sortConnLines(connLines []connLine) {
	sort.Slice(connLines, func(i, j int) bool {
		if connLines[i].Src.NameForAnalyzerOut(nil) != connLines[j].Src.NameForAnalyzerOut(nil) {
			return connLines[i].Src.NameForAnalyzerOut(nil) < connLines[j].Src.NameForAnalyzerOut(nil)
		}
		return connLines[i].Dst.NameForAnalyzerOut(nil) < connLines[j].Dst.NameForAnalyzerOut(nil)
	})
}

type allInfo struct {
	EndpointsConnectivity []connLine `json:"endpoints_connectivity"`
}

func getConnLines(conn *VPCConnectivity) []connLine {
	connLines := []connLine{}

	for src, srcMap := range conn.AllowedConnsCombinedResponsive {
		for dst, extConn := range srcMap {
			if extConn.isEmpty() {
				continue
			}
			responsiveAndOther := extConn.tcpRspEnable.Union(extConn.nonTCP)
			if !extConn.TCPRspDisable.IsEmpty() {
				connLines = append(connLines, connLine{Src: src, Dst: dst, Conn: netset.ToJSON(responsiveAndOther),
					UnidirectionalConn: netset.ToJSON(extConn.TCPRspDisable)})
			} else {
				connLines = append(connLines, connLine{Src: src, Dst: dst, Conn: netset.ToJSON(extConn.allConn)})
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
	for src, nodeConns := range conn.AllowedConnsCombinedResponsive {
		for dst, extConns := range nodeConns {
			if extConns.isEmpty() {
				continue
			}
			// currently, not supported with grouping
			connLines = append(connLines, connLine{
				Src:                src,
				Dst:                dst,
				Conn:               netset.ToJSON(extConns.tcpRspEnable.Union(extConns.nonTCP)),
				UnidirectionalConn: netset.ToJSON(extConns.TCPRspDisable),
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
		if diffLines[i].Src.NameForAnalyzerOut(nil) != diffLines[j].Src.NameForAnalyzerOut(nil) {
			return diffLines[i].Src.NameForAnalyzerOut(nil) < diffLines[j].Src.NameForAnalyzerOut(nil)
		}
		return diffLines[i].Dst.NameForAnalyzerOut(nil) < diffLines[j].Dst.NameForAnalyzerOut(nil)
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
				src, dst, netset.ToJSON(connDiff.conn1.nonTCPAndResponsiveTCPComponent()),
				netset.ToJSON(connDiff.conn1.TCPRspDisable),
				netset.ToJSON(connDiff.conn2.nonTCPAndResponsiveTCPComponent()),
				netset.ToJSON(connDiff.conn2.TCPRspDisable)})
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
