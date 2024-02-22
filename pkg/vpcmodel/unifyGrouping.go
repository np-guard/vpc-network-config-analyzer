package vpcmodel

// UnifyMultiVPC unifies multi-vpc graph for endpoints and subnets connectivity s.t.
// each node appears once across multi-vpcs this is relevant only for DRAWIO and ARCHDRAWIO
func UnifyMultiVPC(config1, config2 map[string]*VPCConfig, nodesConn map[string]*VPCConnectivity,
	subnetsConn map[string]*VPCsubnetConnectivity, f OutFormat) {
	groupedEndpointsElemsMap := map[string]*groupedEndpointsElems{}
	groupedExternalNodesMap := map[string]*groupedExternalNodes{}
	if f != DRAWIO && f != ARCHDRAWIO {
		return
	}
	for vpcName := range config1 {
		if VPCconnectivity, ok1 := nodesConn[vpcName]; ok1 {
			if len(VPCconnectivity.GroupedConnectivity.GroupedLines) > 0 {
				VPCconnectivity.GroupedConnectivity.GroupedLines =
					unifiedGroupedConnLines(VPCconnectivity.GroupedConnectivity.GroupedLines,
						groupedEndpointsElemsMap, groupedExternalNodesMap, false)
			}

		}
	}
	return
}

// Go over the grouping result and make sure all groups have a unified reference.
// this is required due to the functionality treating self loops as don't cares - extendGroupingSelfLoops
// in which both srcs and dsts are manipulated  but *GroupConnLines is not familiar
// within the extendGroupingSelfLoops context and thus can not be done there smoothly
func unifiedGroupedConnLines(oldConnLines []*groupedConnLine,
	groupedEndpointsElemsMap map[string]*groupedEndpointsElems,
	groupedExternalNodesMap map[string]*groupedExternalNodes,
	unifyGroupedExternalNodes bool) []*groupedConnLine {
	newGroupedLines := make([]*groupedConnLine, len(oldConnLines))
	// go over all connections; if src/dst is not external then use groupedEndpointsElemsMap
	for i, groupedLine := range oldConnLines {
		newGroupedLines[i] = &groupedConnLine{unifiedGroupedElems(groupedLine.src, groupedEndpointsElemsMap,
			groupedExternalNodesMap, unifyGroupedExternalNodes),
			unifiedGroupedElems(groupedLine.dst, groupedEndpointsElemsMap,
				groupedExternalNodesMap, unifyGroupedExternalNodes),
			groupedLine.commonProperties}
	}
	return newGroupedLines
}

func unifiedGroupedElems(srcOrDst EndpointElem,
	groupedEndpointsElemsMap map[string]*groupedEndpointsElems,
	groupedExternalNodesMap map[string]*groupedExternalNodes,
	unifyGroupedExternalNodes bool) EndpointElem {
	// external in case external grouping does not need to be unifed
	if !unifyGroupedExternalNodes && srcOrDst.IsExternal() {
		return srcOrDst
	}
	if _, ok := srcOrDst.(Node); ok { // vsi or single node external address
		return srcOrDst
	}
	if _, ok := srcOrDst.(NodeSet); ok { // subnet
		return srcOrDst
	}
	if groupedEE, ok := srcOrDst.(*groupedEndpointsElems); ok {
		unifiedGroupedEE := getGroupedEndpointsElems(*groupedEE, groupedEndpointsElemsMap)
		return unifiedGroupedEE
	}
	if groupedExternal, ok := srcOrDst.(*groupedExternalNodes); ok {
		unifiedGroupedEE := getGroupedExternalNodes(*groupedExternal, groupedExternalNodesMap)
		return unifiedGroupedEE
	}
	return srcOrDst
}

// Go over the grouping result and make sure all groups have a unified reference.
func unifiedSingleGroupedConnLines(oldConnLines []*groupedConnLine,
	groupedEndpointsElemsMap map[string]*groupedEndpointsElems,
	groupedExternalNodesMap map[string]*groupedExternalNodes) []*groupedConnLine {
	newGroupedLines := make([]*groupedConnLine, len(oldConnLines))
	// go over all connections; if src/dst is not external then use groupedEndpointsElemsMap
	for i, groupedLine := range oldConnLines {
		newGroupedLines[i] = &groupedConnLine{unifiedGroupedElems(groupedLine.src, groupedEndpointsElemsMap, groupedExternalNodesMap, false),
			unifiedGroupedElems(groupedLine.dst, groupedEndpointsElemsMap, groupedExternalNodesMap, false),
			groupedLine.commonProperties}
	}
	return newGroupedLines
}

// given a groupedEndpointsElems returns an equiv item from groupedEndpointsElemsMap if exists,
// or adds it to groupedEndpointsElemsMap if such an item does not exist
func getGroupedEndpointsElems(grouped groupedEndpointsElems,
	groupedEndpointsElemsMap map[string]*groupedEndpointsElems) *groupedEndpointsElems {
	// since the endpoints (vsis/subnets) are sorted before printed, grouped.Name() will be identical
	// to equiv groupedEndpointsElems
	if existingGrouped, ok := groupedEndpointsElemsMap[grouped.Name()]; ok {
		return existingGrouped
	}
	groupedEndpointsElemsMap[grouped.Name()] = &grouped
	return &grouped
}

// same as the previous function, for groupedExternalNodesMap
func getGroupedExternalNodes(grouped groupedExternalNodes,
	groupedExternalNodesMap map[string]*groupedExternalNodes) *groupedExternalNodes {
	// Due to the canonical representation, grouped.String() and thus grouped.Name() will be identical
	//  to equiv groupedExternalNodes
	if existingGrouped, ok := groupedExternalNodesMap[grouped.Name()]; ok {
		return existingGrouped
	}
	groupedExternalNodesMap[grouped.Name()] = &grouped
	return &grouped
}
