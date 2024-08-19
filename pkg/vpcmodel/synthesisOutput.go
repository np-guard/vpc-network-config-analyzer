/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"encoding/json"
	"sort"
	"strconv"

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
		all = getSynthesisSpec(conn.GroupedConnectivity.GroupedLines)
	case AllSubnets:
		all = getSynthesisSpec(subnetsConn.GroupedConnectivity.GroupedLines)
	}
	outStr, err := writeJSON(all, outFile)
	v2Name := ""
	if c2 != nil {
		v2Name = c2.VPC.Name()
	}
	return &SingleAnalysisOutput{Output: outStr, VPC1Name: c1.VPC.Name(), VPC2Name: v2Name, format: Synthesis, jsonStruct: all}, err
}

func handleExternals(srcName, cidrOrAddress string, externalsMap map[string]string, externals spec.SpecExternals) string {
	if val, ok := externalsMap[srcName]; ok {
		return val
	}
	name := "external" + strconv.Itoa(len(externals))
	externalsMap[srcName] = name
	externals[name] = cidrOrAddress
	return name
}

func handleNameAndType(resource EndpointElem, externalsMap map[string]string, externals spec.SpecExternals) (
	resourceName string,
	resourceType spec.ResourceType) {
	resourceName = resource.SynthesisResourceName()
	if resource.IsExternal() {
		if structObj, ok := resource.(*groupedExternalNodes); ok {
			// should be always true if src is external
			resourceName = handleExternals(resourceName, structObj.CidrOrAddress(), externalsMap, externals)
		}
	}
	resourceType = resource.SynthesisKind()
	return
}

func getSynthesisSpec(groupedLines []*groupedConnLine) spec.Spec {
	s := spec.Spec{}
	connLines := []spec.SpecRequiredConnectionsElem{}
	externals := spec.SpecExternals{}
	externalsMap := make(map[string]string)
	sortGroupedLines(groupedLines)

	for _, groupedLine := range groupedLines {
		srcName, srcType := handleNameAndType(groupedLine.Src, externalsMap, externals)
		dstName, dstType := handleNameAndType(groupedLine.Dst, externalsMap, externals)
		if groupedLine.CommonProperties.Conn.isEmpty() {
			continue
		}
		// For now, ignoring responsiveness of TCP connection
		connLines = append(connLines, spec.SpecRequiredConnectionsElem{
			Src:              spec.Resource{Name: srcName, Type: srcType},
			Dst:              spec.Resource{Name: dstName, Type: dstType},
			AllowedProtocols: sortProtocolList(spec.ProtocolList(connection.ToJSON(groupedLine.CommonProperties.Conn.allConn)))})
	}
	s.Externals = externals
	s.RequiredConnections = connLines
	return s
}

func sortProtocolList(g spec.ProtocolList) spec.ProtocolList {
	sort.Slice(g, func(i, j int) bool {
		iMarshal, _ := json.Marshal(g[i])
		jMarshal, _ := json.Marshal(g[j])
		return string(iMarshal) > string(jMarshal)
	})
	return g
}

func sortGroupedLines(g []*groupedConnLine) {
	sort.Slice(g, func(i, j int) bool {
		if g[i].Src.Name() != g[j].Src.Name() {
			return g[i].Src.Name() > g[j].Src.Name()
		} else if g[i].Dst.Name() != g[j].Dst.Name() {
			return g[i].Dst.Name() > g[j].Dst.Name()
		}
		return g[i].CommonProperties.Conn.string() > g[j].CommonProperties.Conn.string()
	})
}
