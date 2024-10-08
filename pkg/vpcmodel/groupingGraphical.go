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
	// 1. Get a map from name to grouped external
	nameExternalToObject := map[string]groupedExternalNodes{}
	getMapNameGroupedExternalToObject(nameExternalToObject, g.srcToDst)
	getMapNameGroupedExternalToObject(nameExternalToObject, g.dstToSrc)
	// 2. Get a map from grouped external name to their IPs
	nameExternalToIpBlock := map[string]*ipblock.IPBlock{}
	getMapNameGroupedExternalToIP(nameExternalToIpBlock, g.srcToDst)
	getMapNameGroupedExternalToIP(nameExternalToIpBlock, g.dstToSrc)
	// 3. Check for containment of ips via nameToIpBlock
	containedMap := findContainEndpointMap(nameExternalToIpBlock)
	_ = containedMap
	// 4. Add edges
	//g.addEdgesOfContainingEPs(containedMap, nameExternalToObject)
}

// gets *groupingConnections and returns a map from the string presentation of each grouped external to its object
func getMapNameGroupedExternalToObject(nameToGroupedExternal map[string]groupedExternalNodes, grouped *groupingConnections) {
	for _, groupedInfoMap := range *grouped { //groupedExternalNodes
		for _, groupedInfo := range groupedInfoMap {
			name := groupedInfo.nodes.Name()
			_, ok := nameToGroupedExternal[name]
			if ok { // no need to update twice; relevant if the same endpoint is in src and dst of different lines
				return
			}
			nameToGroupedExternal[name] = groupedInfo.nodes
		}
	}
}

// gets *groupingConnections and returns a map from the string presentation of each grouped external to its ipBlock
func getMapNameGroupedExternalToIP(nameToIpBlock map[string]*ipblock.IPBlock, grouped *groupingConnections) {
	for _, groupedInfoMap := range *grouped { //groupedExternalNodes
		for _, groupedInfoMap := range groupedInfoMap {
			addGroupedExternalNode(groupedInfoMap.nodes, nameToIpBlock)
		}
	}
}

func addGroupedExternalNode(externalNodes groupedExternalNodes, endpointsIPBlocks map[string]*ipblock.IPBlock) {
	_, ok := endpointsIPBlocks[externalNodes.Name()]
	if ok { // no need to update twice; relevant if the same endpoint is in src and dst of different lines
		return
	}
	endpointsIPBlocks[externalNodes.Name()] = groupedExternalToIpBlock(externalNodes)
}

func groupedExternalToIpBlock(externalNodes groupedExternalNodes) *ipblock.IPBlock {
	// EndpointElem must be of type groupedExternalNodes
	elements := []*ExternalNetwork(externalNodes)
	var res = ipblock.New()
	for _, e := range elements {
		res = res.Union(e.ipblock)
	}
	return res
}

// given a map from external endpoints to their IPs returns a map from each endpoint to the endpoints that it contains
// (if any)
func findContainEndpointMap(endpointsIPBlocks map[string]*ipblock.IPBlock) (containedMap map[string][]string) {
	containedMap = map[string][]string{}
	for containingEP, containingIP := range endpointsIPBlocks {
		containedEPs := []string{}
		for containedEP, containedIP := range endpointsIPBlocks {
			if containingEP == containedEP {
				continue
			}
			if containedIP.ContainedIn(containingIP) {
				containedEPs = append(containedEPs, containedEP)
			}
		}
		if len(containedEPs) > 0 {
			containedMap[containingEP] = containedEPs
		}
	}
	return containedMap
}

//// given the above containedMap adds edges of containing endpoints
//func (g *GroupConnLines) addEdgesOfContainingEPs(containedMap map[string][]string,
//	nameExternalToObject map[string]*groupedExternalNodesInfo) {
//	for _, toAddEdgesLine := range g.GroupedLines {
//		g.addEdgesToLine(toAddEdgesLine, containedMap, true)
//		g.addEdgesToLine(toAddEdgesLine, containedMap, false)
//	}
//}
//
//func (g *GroupConnLines) addEdgesToLine(line *groupedConnLine, endpointToLines map[string][]*groupedConnLine,
//	containedMap map[string][]string, src bool) {
//	fmt.Println("here")
//	nameToEndpointElem := map[string]EndpointElem{}
//	res := []*groupedConnLine{} // dummy place holder for addLineToExternalGrouping
//	for _, line := range g.GroupedLines {
//		// there could be rewriting with identical values; not an issue complexity wise, not checking this keeps the code simpler
//		nameToEndpointElem[line.Src.NameForAnalyzerOut(g.config)] = line.Src
//		nameToEndpointElem[line.Dst.NameForAnalyzerOut(g.config)] = line.Dst
//	}
//	var addToNodeName string
//	if src {
//		addToNodeName = line.Src.NameForAnalyzerOut(g.config)
//	} else {
//		addToNodeName = line.Dst.NameForAnalyzerOut(g.config)
//	}
//	for _, containedEndpoint := range containedMap[addToNodeName] {
//		for _, toAddLine := range endpointToLines[containedEndpoint] {
//			fmt.Printf("about to add to %v line %v => %v\n", addToNodeName,
//				toAddLine.Src.NameForAnalyzerOut(g.config), toAddLine.Dst.NameForAnalyzerOut(g.config))
//			// adding edges - namely, lines in grouping. "This" end of the edge is external (by design) and the "other"
//			// end of the edges will always be internal, since "this" edge is not internal.
//			// Grouping per is done after this point
//			if src {
//				g.addLineToExternalGrouping(&res, nameToEndpointElem[addToNodeName], toAddLine.Dst,
//					toAddLine.CommonProperties)
//			} else {
//				g.addLineToExternalGrouping(&res, toAddLine.Src, nameToEndpointElem[addToNodeName],
//					toAddLine.CommonProperties)
//			}
//		}
//	}
//}
