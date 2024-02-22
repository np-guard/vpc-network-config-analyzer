package vpcmodel

// UnifyMultiVPC unifies multi-vpc graph for endpoints and subnets connectivity s.t.
// each node appears once across multi-vpcs this is relevant only for DRAWIO and ARCHDRAWIO
// in which there is a multivpc presentation
func UnifyMultiVPC(config1 map[string]*VPCConfig, nodesConn map[string]*VPCConnectivity,
	subnetsConn map[string]*VPCsubnetConnectivity, f OutFormat) {
	groupedEndpointsElemsMap := map[string]*groupedEndpointsElems{}
	groupedExternalNodesMap := map[string]*groupedExternalNodes{}
	if f != DRAWIO && f != ARCHDRAWIO {
		return
	}
	for vpcName := range config1 {
		if VPCconnectivity, ok := nodesConn[vpcName]; ok {
			if len(VPCconnectivity.GroupedConnectivity.GroupedLines) > 0 {
				VPCconnectivity.GroupedConnectivity.GroupedLines =
					unifiedGroupedConnLines(VPCconnectivity.GroupedConnectivity.GroupedLines,
						groupedEndpointsElemsMap, groupedExternalNodesMap, true)
			}
		}
		if subnetConnectivity, ok := subnetsConn[vpcName]; ok {
			if len(subnetConnectivity.GroupedConnectivity.GroupedLines) > 0 {
				subnetConnectivity.GroupedConnectivity.GroupedLines =
					unifiedGroupedConnLines(subnetConnectivity.GroupedConnectivity.GroupedLines,
						groupedEndpointsElemsMap, groupedExternalNodesMap, true)
			}
		}
	}
	return
}

// Go over the grouping result and set groups s.t. all semantically equiv groups have a unified reference.
// this is required for multivpc's context and at the end of the grouping in a single vpc context
// the former is required since each vpc analysis and grouping is done separately
// the latter is required due to the functionality treating self loops as don't cares - extendGroupingSelfLoops
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

// unifies reference to a single element
func unifiedGroupedElems(srcOrDst EndpointElem,
	groupedEndpointsElemsMap map[string]*groupedEndpointsElems,
	groupedExternalNodesMap map[string]*groupedExternalNodes,
	unifyGroupedExternalNodes bool) EndpointElem {
	// external in case external grouping does not need to be unifed
	if !unifyGroupedExternalNodes && srcOrDst.IsExternal() {
		return srcOrDst
	}
	if _, ok := srcOrDst.(Node); ok { // single vsi or single node external address
		return srcOrDst
	}
	if _, ok := srcOrDst.(NodeSet); ok { // single subnet
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
