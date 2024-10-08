/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"fmt"
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
func (g *GroupConnLines) consistencyEdgesExternal() error {
	// 1. Get a map from name to grouped external
	nameExternalToNodes := map[string]groupedExternalNodes{}
	getMapNameGroupedExternalToNodes(nameExternalToNodes, g.srcToDst)
	getMapNameGroupedExternalToNodes(nameExternalToNodes, g.dstToSrc)
	// 2. Get a map from grouped external name to their IPs
	nameExternalToIpBlock := map[string]*ipblock.IPBlock{}
	getMapNameGroupedExternalToIP(nameExternalToIpBlock, g.srcToDst)
	getMapNameGroupedExternalToIP(nameExternalToIpBlock, g.dstToSrc)
	// 3. Check for containment of ips via nameToIpBlock
	containedMap := findContainEndpointMap(nameExternalToIpBlock)
	// 4. Add edges to g.srcToDst and to g.dstToSrc
	err1 := g.addEdgesToGroupedConnection(true, containedMap, nameExternalToNodes)
	if err1 != nil {
		return err1
	}
	err2 := g.addEdgesToGroupedConnection(false, containedMap, nameExternalToNodes)
	if err2 != nil {
		return err2
	}
	return nil
}

func (g *GroupConnLines) printSrcToDst() {
	fmt.Println("g.srcToDst\n~~~~~~~~~~~~~~~~")
	for src, object := range *g.srcToDst {
		for _, externalInfo := range object {
			fmt.Printf("\t%v => %v %v\n", src.NameForAnalyzerOut(g.config), externalInfo.nodes.Name(), externalInfo.commonProperties.Conn.string())
		}
	}
}

func (g *groupingConnections) printGroupingConnections() {
	fmt.Println("groupingConnections\n~~~~~~~~~~~~~~~~")
	for src, object := range *g {
		for _, externalInfo := range object {
			fmt.Printf("\t%v => %v %v\n", src.Name(), externalInfo.nodes.Name(), externalInfo.commonProperties.Conn.string())
		}
	}
}

// gets *groupingConnections and returns a map from the string presentation of each grouped external to its nodes
func getMapNameGroupedExternalToNodes(nameToGroupedExternal map[string]groupedExternalNodes, grouped *groupingConnections) {
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

// goes over g.srcToDst and over g.dstToSrc; for each "edge" represented by these structs of from/to external nodes,
// duplicates the edge to all "external nodes" entities that are contained in the external node of the edge
func (g *GroupConnLines) addEdgesToGroupedConnection(src bool, containedMap map[string][]string,
	nameExternalToNodes map[string]groupedExternalNodes) (err error) {
	fmt.Println("addEdgesToGroupedConnection")
	var groupedConnectionToAddBy *groupingConnections
	if src {
		groupedConnectionToAddBy = g.srcToDst
	} else {
		groupedConnectionToAddBy = g.dstToSrc
	}
	for srcOrDstEP, object := range *groupedConnectionToAddBy {
		for _, groupedExternalInfo := range object {
			// checks whether the groupedExternalNodes contains other groupedExternalNodes that are in the graph,
			// in which case the line should be added to the contained groupedExternalNodes
			contained, ok := containedMap[groupedExternalInfo.nodes.Name()]
			if !ok {
				continue
			}
			res := []*groupedConnLine{} // dummy placeholder for addLineToExternalGrouping
			// goes over all external nodes contained in the node of groupedExternalInfo; the "edge" represented by
			// <srcOrDstEP to containingObject> should be duplicated for these external nodes
			for _, containedName := range contained {
				containedNodes := nameExternalToNodes[containedName]
				externalNodes := []*ExternalNetwork(containedNodes)
				for _, node := range externalNodes {
					if src {
						err = g.addLineToExternalGrouping(&res, srcOrDstEP, node,
							groupedExternalInfo.commonProperties)
					} else {
						err = g.addLineToExternalGrouping(&res, node, srcOrDstEP,
							groupedExternalInfo.commonProperties)
					}
				}
			}
		}
	}
	return err
}
