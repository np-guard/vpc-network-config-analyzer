/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"github.com/np-guard/models/pkg/ipblock"
)

// for the graphical (html, drawio, svg) representation. In the graph presentation, each node must have all relevant edges.
// this is not the case in the textual presentation. E.g., a textual presentation may look like:
// 142.0.64.0/17 ->vsi2
// 142.0.0.0/16 -> vsi1
// 0.0.0.0/0 -> vsi3
// 142.0.64.0/17 should also be connected to vsi1 and vsi3
// In order to add missing edges, we go over all the endpoints in grouping that present external nodes, and check for containment
// if external endpoint e1 is contained in external end point e2 then all the "edges" of e2 are added to e1
func (g *GroupConnLines) consistencyEdgesExternal() {
	// 1. Gets a map from external endpoints name to their IPs
	eeNameToIPBlock := getMapToIps(g.GroupedLines)
	// 2. Gets a map from external endpoints name to their endpoint
	eeNameToEE := getMapToEPEs(g.GroupedLines)
	// 3. Gets a map from external endpoint name to all the endpoint it contains
	containedMap := getContainedEndpointMap(eeNameToIPBlock, eeNameToEE)
	// 4. Add edges, based on the above map (3)
	g.addEdgesOfContainingEPs(containedMap)
}

// gets []*groupedConnLine and returns a map from the string presentation of each endpoint to its ipBlock
func getMapToIps(grouped []*groupedConnLine) (eeToIPBlock map[string]*ipblock.IPBlock) {
	eeToIPBlock = map[string]*ipblock.IPBlock{}
	for _, line := range grouped {
		addExternalEndpointToMap(line.Src, eeToIPBlock)
		addExternalEndpointToMap(line.Dst, eeToIPBlock)
	}
	return eeToIPBlock
}

// gets []*groupedConnLine and returns a map from the string presentation of each endpoint to the endpoint element
func getMapToEPEs(grouped []*groupedConnLine) (eeNameToEE map[string]EndpointElem) {
	eeNameToEE = map[string]EndpointElem{}
	for _, line := range grouped {
		if line.Src.IsExternal() {
			eeNameToEE[line.Src.Name()] = line.Src
		} else if line.Dst.IsExternal() {
			eeNameToEE[line.Dst.Name()] = line.Dst
		}
	}
	return eeNameToEE
}

func addExternalEndpointToMap(ee EndpointElem, endpointsIPBlocks map[string]*ipblock.IPBlock) {
	if !ee.IsExternal() {
		return
	}
	_, ok := endpointsIPBlocks[ee.Name()]
	if ok { // no need to update twice; relevant if the same endpoint is in src and dst of different lines
		return
	}
	endpointsIPBlocks[ee.Name()] = groupedExternalToIPBlock(ee)
}

func groupedExternalToIPBlock(ee EndpointElem) *ipblock.IPBlock {
	// EndpointElem must be of type groupedExternalNodes
	elements := []*ExternalNetwork(*ee.(*groupedExternalNodes))
	var res = ipblock.New()
	for _, e := range elements {
		res = res.Union(e.ipblock)
	}
	return res
}

// given a map from external endpoints to their IPs returns a map from each endpoint to the endpoints that
// it contained (if any)
func getContainedEndpointMap(endpointsIPBlocks map[string]*ipblock.IPBlock,
	eeNameToEE map[string]EndpointElem) (containedMap map[string][]EndpointElem) {
	containedMap = map[string][]EndpointElem{}
	for containingEP, containingIP := range endpointsIPBlocks {
		containedEPs := []EndpointElem{}
		for containedEP, containedIP := range endpointsIPBlocks {
			if containedEP == containingEP {
				continue
			}
			if containedIP.ContainedIn(containingIP) {
				containedEPs = append(containedEPs, eeNameToEE[containedEP])
			}
		}
		if len(containedEPs) > 0 {
			containedMap[containingEP] = containedEPs
		}
	}
	return containedMap
}

// iterates over all grouped lines, and for each line adds edges implied by it
func (g *GroupConnLines) addEdgesOfContainingEPs(containedMap map[string][]EndpointElem) {
	for _, line := range g.GroupedLines {
		g.addEdgesImpliedOfLine(line, containedMap)
	}
}

// Given a grouping line - l - if one of its ends - e -  is external, adds implied edges to all contained external nodes.
// Specifically, iterates over the contained external nodes of e, and for each such node - c -
// adds a line whose internal endpoint is the same as l and external endpoint is c
func (g *GroupConnLines) addEdgesImpliedOfLine(line *groupedConnLine, containedMap map[string][]EndpointElem) {
	srcExternal := line.Src.IsExternal()
	dstExternal := line.Dst.IsExternal()
	if !srcExternal && !dstExternal {
		return
	}
	var containingNode EndpointElem
	switch {
	// by design, either src or dst can not be both external
	case srcExternal:
		containingNode = line.Src
	case dstExternal:
		containingNode = line.Dst
	default:
		return
	}
	for _, containedExternal := range containedMap[containingNode.Name()] {
		// adding edges - namely, lines in grouping. "This" end of the edge is external (by design) and the "other"
		// end of the edges will always be internal, since "this" edge is not internal.
		// Grouping per internal endpoints is done (if requested) after this point
		if srcExternal {
			g.GroupedLines = append(g.GroupedLines, &groupedConnLine{Src: containedExternal,
				Dst: line.Dst, CommonProperties: line.CommonProperties})
		} else { // dstExternal
			g.GroupedLines = append(g.GroupedLines, &groupedConnLine{Src: line.Src,
				Dst: containedExternal, CommonProperties: line.CommonProperties})
		}
	}
}
