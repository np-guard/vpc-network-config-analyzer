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
// 142.0.64.0/17 should also be connected to vsi2 and vsi3
// In order to add missing edges, we go over all the endpoints that present external nodes, and check for containment
// if external endpoint e1 is contained in external end point e2 then all the "edges" of e2 should be added to e1
func (g *GroupConnLines) consistencyEdgesExternal() {
	// 1. Get a map from external endpoints to their IPs
	eeToIpBlock := getMapToGroupedExternalBlocks(g.GroupedLines)
	// 2. Check for containment
	containedMap := findContainEndpointMap(eeToIpBlock)
	// 3. Add edges
	g.addEdgesOfContainingEPs(containedMap)
}

// gets []*groupedConnLine and returns a map from the string presentation of each endpoint to its ipBlock
func getMapToGroupedExternalBlocks(grouped []*groupedConnLine) (eeToIpBlock map[string]*ipblock.IPBlock) {
	eeToIpBlock = map[string]*ipblock.IPBlock{}
	for _, line := range grouped {
		addExternalEndpointToMap(line.Src, eeToIpBlock)
		addExternalEndpointToMap(line.Dst, eeToIpBlock)
	}
	return eeToIpBlock
}

func addExternalEndpointToMap(ee EndpointElem, endpointsIPBlocks map[string]*ipblock.IPBlock) {
	if !ee.IsExternal() {
		return
	}
	_, ok := endpointsIPBlocks[ee.Name()]
	if ok { // no need to update twice; relevant if the same endpoint is in src and dst of different lines
		return
	}
	endpointsIPBlocks[ee.Name()] = groupedExternalToIpBlock(ee)
}

func groupedExternalToIpBlock(ee EndpointElem) *ipblock.IPBlock {
	// EndpointElem must be of type groupedExternalNodes
	elements := []*ExternalNetwork(*ee.(*groupedExternalNodes))
	var res = ipblock.New()
	for _, e := range elements {
		res = res.Union(e.ipblock)
	}
	return res
}

// given a map from external endpoints to their IPs returns a map from each endpoint to the endpoints that contains it
// (if any)
func findContainEndpointMap(endpointsIPBlocks map[string]*ipblock.IPBlock) (containedMap map[string][]string) {
	containedMap = map[string][]string{}
	for containedEP, containedIP := range endpointsIPBlocks {
		containingEPs := []string{}
		for containingEP, containingIP := range endpointsIPBlocks {
			if containingEP == containedEP {
				continue
			}
			if containedIP.ContainedIn(containingIP) {
				containingEPs = append(containingEPs, containingEP)
			}
		}
		if len(containingEPs) > 0 {
			containedMap[containedEP] = containingEPs
		}
	}
	return containedMap
}

// given the above containedMap adds edges of containing endpoints
func (g *GroupConnLines) addEdgesOfContainingEPs(containedMap map[string][]string) {
	endpointToLines := g.getEndpointToLines() // auxiliary map between each endpoint element to lines it participates in
	// (as src or dst)
	for _, toAddEdgesLine := range g.GroupedLines {
		g.addEdgesToLine(toAddEdgesLine, endpointToLines, containedMap, true)
		g.addEdgesToLine(toAddEdgesLine, endpointToLines, containedMap, false)
	}
}

// creates an auxiliary map between each endpoint element to all the lines it participates in (as src or dst)
func (g *GroupConnLines) getEndpointToLines() (endpointToLines map[string][]*groupedConnLine) {
	endpointToLines = map[string][]*groupedConnLine{}
	for _, line := range g.GroupedLines {
		addLineToMap(endpointToLines, line, true)
		addLineToMap(endpointToLines, line, false)
	}
	return endpointToLines
}

func addLineToMap(endpointToLines map[string][]*groupedConnLine, line *groupedConnLine, src bool) {
	var name string
	if src {
		name = line.Src.Name()
	} else {
		name = line.Dst.Name()
	}
	if _, ok := endpointToLines[name]; !ok {
		endpointToLines[name] = []*groupedConnLine{}
	}
	endpointToLines[name] = append(endpointToLines[name], line)
}

func (g *GroupConnLines) addEdgesToLine(line *groupedConnLine, endpointToLines map[string][]*groupedConnLine,
	containedMap map[string][]string, src bool) {
	nameToEndpointElem := map[string]EndpointElem{}
	for _, line := range g.GroupedLines {
		// there could be rewriting with identical values; not an issue complexity wise, not checking this keeps the code simpler
		nameToEndpointElem[line.Src.Name()] = line.Src
		nameToEndpointElem[line.Dst.Name()] = line.Dst
	}
	var addToNodeName string
	if src {
		addToNodeName = line.Src.Name()
	} else {
		addToNodeName = line.Dst.Name()
	}
	for _, containedEndpoint := range containedMap[addToNodeName] {
		for _, toAddLine := range endpointToLines[containedEndpoint] {
			// adding edges - namely, lines in grouping. "This" end of the edge is external (by design) and the "other"
			// end of the edges will always be internal, since "this" edge is not internal.
			// Grouping per internal endpoints is done (if requested) after this point
			switch {
			case src && toAddLine.Src.Name() == addToNodeName:
				g.GroupedLines = append(g.GroupedLines, &groupedConnLine{Src: nameToEndpointElem[addToNodeName],
					Dst: toAddLine.Dst, CommonProperties: toAddLine.CommonProperties})
			case !src && toAddLine.Dst.Name() == addToNodeName:
				g.GroupedLines = append(g.GroupedLines, &groupedConnLine{Src: toAddLine.Src,
					Dst: nameToEndpointElem[addToNodeName], CommonProperties: toAddLine.CommonProperties})
			}
		}
	}
}
