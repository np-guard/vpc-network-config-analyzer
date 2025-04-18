/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/models/pkg/spec"
	common "github.com/np-guard/vpc-network-config-analyzer/pkg/common"
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
		if grouping {
			return nil, errors.New("report endpoints in synthesis format with grouping is not supported")
		}
		all = getSynthesisSpec(conn.GroupedConnectivity.GroupedLines, grouping)
	case AllSubnets:
		all = getSynthesisSpec(subnetsConn.GroupedConnectivity.GroupedLines, grouping)
	}
	outStr, err := writeJSON(all, outFile)
	v2Name := ""
	if c2 != nil {
		v2Name = c2.VPC.Name()
	}
	return &SingleAnalysisOutput{Output: outStr, VPC1Name: c1.VPC.Name(),
		VPC2Name: v2Name, format: Synthesis, jsonStruct: all}, err
}

func handleNameAndType(resource EndpointElem, externals spec.SpecExternals, segments spec.SpecSegments, grouping bool) (
	resourceName string, resourceType spec.ResourceType) {
	resourceName = resource.SynthesisResourceName()
	resourceType = resource.SynthesisKind()
	if resource.IsExternal() {
		if groupObj, ok := resource.(*groupedExternalNodes); ok {
			// should be always true if src is external"
			// later in aggregate we change the name with other vpc configs
			externals[resourceName] = groupObj.CidrOrAddress()
		}
	}
	if grouping && !resource.IsExternal() {
		if groupObj, ok := resource.(*groupedEndpointsElems); ok {
			// should be always true if src is internal"
			// later in aggregate we change the name with other vpc configs
			if len(*groupObj) > 1 {
				segments[resourceName] = spec.Segment{Items: groupObj.AsNamesList(), Type: spec.SegmentTypeSubnet}
			} else {
				// grouping in synthesis only allowed with subnets
				resourceType = spec.ResourceTypeSubnet
			}
		}
	}
	return
}

func getSynthesisSpec(groupedLines []*groupedConnLine, grouping bool) *spec.Spec {
	s := spec.Spec{}
	connLines := []spec.SpecRequiredConnectionsElem{}
	externals := spec.SpecExternals{}
	segments := spec.SpecSegments{}
	sortGroupedLines(groupedLines)
	bidirectionalMap := makeBidirectionalMap(groupedLines)
	for _, groupedLine := range groupedLines {
		if groupedLine.CommonProperties.Conn.isEmpty() {
			continue
		}
		srcName, srcType := handleNameAndType(groupedLine.Src, externals, segments, grouping)
		dstName, dstType := handleNameAndType(groupedLine.Dst, externals, segments, grouping)
		bidirectional, ok := bidirectionalMap[getBidirectionalMapKeyByConnLine(groupedLine, false)]

		if !ok {
			// it means that it is bidirectional but the conn line will be appended to the list with the other direction.
			continue
		}

		connLines = append(connLines, spec.SpecRequiredConnectionsElem{
			Src:              spec.Resource{Name: srcName, Type: srcType},
			Dst:              spec.Resource{Name: dstName, Type: dstType},
			AllowedProtocols: sortProtocolList(spec.ProtocolList(netset.ToJSON(groupedLine.CommonProperties.Conn.allConn))),
			Bidirectional:    bidirectional})
	}
	s.Externals = externals
	s.RequiredConnections = connLines
	s.Segments = segments
	return &s
}

func getBidirectionalMapKeyByNames(firstName, secName, conn string) string {
	return fmt.Sprintf("%s_%s_%s", firstName, secName, conn)
}

func getBidirectionalMapKeyByConnLine(groupedLine *groupedConnLine, flip bool) string {
	if flip {
		return getBidirectionalMapKeyByNames(groupedLine.Dst.SynthesisResourceName(),
			groupedLine.Src.SynthesisResourceName(),
			common.LongString(groupedLine.CommonProperties.Conn.allConn))
	}
	return getBidirectionalMapKeyByNames(groupedLine.Src.SynthesisResourceName(),
		groupedLine.Dst.SynthesisResourceName(),
		common.LongString(groupedLine.CommonProperties.Conn.allConn))
}

// Returns a map from string(src+dst+conn) to whether the connection is bidirectional.
// When bidirectional, only one direction will be in this map
func makeBidirectionalMap(groupedLines []*groupedConnLine) map[string]bool {
	bidirectionalMap := make(map[string]bool)
	for _, groupedLine := range groupedLines {
		_, ok := bidirectionalMap[getBidirectionalMapKeyByConnLine(groupedLine, true)]
		if ok { // reverse direction is already in the map - just mark it bidirectional
			bidirectionalMap[getBidirectionalMapKeyByConnLine(groupedLine, true)] = true
		} else {
			bidirectionalMap[getBidirectionalMapKeyByConnLine(groupedLine, false)] = false
		}
	}
	return bidirectionalMap
}

func getNewExternalOrSegmentName(externalSegmentName, prefixString string, namesMap map[string]string) string {
	if val, ok := namesMap[externalSegmentName]; ok {
		return val
	}
	name := fmt.Sprintf("%s%d", prefixString, len(namesMap))
	namesMap[externalSegmentName] = name
	return name
}

func renameExternalsAndSegments(requiredConnections []spec.SpecRequiredConnectionsElem,
	externalsMap map[string]string, segmentsMap map[string]string) []spec.SpecRequiredConnectionsElem {
	connLines := []spec.SpecRequiredConnectionsElem{}
	for _, conn := range requiredConnections {
		switch conn.Src.Type {
		case spec.ResourceTypeExternal:
			conn.Src.Name = getNewExternalOrSegmentName(conn.Src.Name, externalString, externalsMap)
		case spec.ResourceTypeSegment:
			conn.Src.Name = getNewExternalOrSegmentName(conn.Src.Name, segmentString, segmentsMap)
		}
		switch conn.Dst.Type {
		case spec.ResourceTypeExternal:
			conn.Dst.Name = getNewExternalOrSegmentName(conn.Dst.Name, externalString, externalsMap)
		case spec.ResourceTypeSegment:
			conn.Dst.Name = getNewExternalOrSegmentName(conn.Dst.Name, segmentString, segmentsMap)
		}
		connLines = append(connLines, conn)
	}
	return connLines
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
