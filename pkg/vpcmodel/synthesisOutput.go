/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"sort"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/spec"
)

type SynthesisOutputFormatter struct {
}

func (j *SynthesisOutputFormatter) WriteOutput(c1, c2 *VPCConfig,
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
		all = spec.Spec{RequiredConnections: getRequiredConnections(conn)}
	case AllSubnets:
		all = spec.Spec{RequiredConnections: getRequiredConnectionsForSubnetsConnectivity(subnetsConn)}
	}
	outStr, err := writeJSON(all, outFile)
	v2Name := ""
	if c2 != nil {
		v2Name = c2.VPC.Name()
	}
	return &SingleAnalysisOutput{Output: outStr, VPC1Name: c1.VPC.Name(), VPC2Name: v2Name, format: Synthesis, jsonStruct: all}, err
}

func getRequiredConnectionsForSubnetsConnectivity(conn *VPCsubnetConnectivity) []spec.SpecRequiredConnectionsElem {
	connLines := []spec.SpecRequiredConnectionsElem{}
	for src, nodeConns := range conn.AllowedConnsCombinedResponsive {
		for dst, extConns := range nodeConns {
			if extConns.isEmpty() {
				continue
			}
			// currently, not supported with grouping
			connLines = append(connLines, spec.SpecRequiredConnectionsElem{
				Src:              spec.Resource{Name: src.Name(), Type: spec.ResourceType(src.Kind())},
				Dst:              spec.Resource{Name: dst.Name(), Type: spec.ResourceType(dst.Kind())},
				AllowedProtocols: spec.ProtocolList(connection.ToJSON(extConns.tcpRspDisable)),
			})
		}
	}

	sortRequiredConnections(connLines)
	return connLines
}

func getRequiredConnections(conn *VPCConnectivity) []spec.SpecRequiredConnectionsElem {
	connLines := []spec.SpecRequiredConnectionsElem{}

	for src, srcMap := range conn.AllowedConnsCombinedResponsive {
		for dst, extConn := range srcMap {
			if extConn.isEmpty() {
				continue
			}
			connLines = append(connLines, spec.SpecRequiredConnectionsElem{
				Src:              spec.Resource{Name: src.Name(), Type: spec.ResourceType(src.Kind())},
				Dst:              spec.Resource{Name: dst.Name(), Type: spec.ResourceType(dst.Kind())},
				AllowedProtocols: spec.ProtocolList(connection.ToJSON(extConn.allConn))})
		}
	}

	sortRequiredConnections(connLines)
	return connLines
}

func sortRequiredConnections(connLines []spec.SpecRequiredConnectionsElem) {
	sort.Slice(connLines, func(i, j int) bool {
		if connLines[i].Src.Name != connLines[j].Src.Name {
			return connLines[i].Src.Name < connLines[j].Src.Name
		}
		return connLines[i].Dst.Name < connLines[j].Dst.Name
	})
}
