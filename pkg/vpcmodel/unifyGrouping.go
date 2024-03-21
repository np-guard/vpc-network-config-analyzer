package vpcmodel

type cacheGroupedElements struct {
	groupedEndpointsElemsMap map[string]*groupedEndpointsElems
	groupedExternalNodesMap  map[string]*groupedExternalNodes
}

func newCacheGroupedElements() *cacheGroupedElements {
	return &cacheGroupedElements{
		map[string]*groupedEndpointsElems{},
		map[string]*groupedExternalNodes{},
	}
}

// unifyMultiVPC unifies multi-vpc graph for endpoints and subnets connectivity s.t.
// each node appears once across multi-vpcs this is relevant only for DRAWIO
// in which there is a multivpc presentation
func unifyMultiVPC(config1 MultipleVPCConfigs, nodesConn map[string]*VPCConnectivity,
	subnetsConn map[string]*VPCsubnetConnectivity, uc OutputUseCase) {
	for vpcUID := range config1 {
		switch uc {
		case AllEndpoints:
			if nodesConn[vpcUID] != nil {
				nodesConn[vpcUID].GroupedConnectivity.GroupedLines =
					unifiedGroupedConnLines(nodesConn[vpcUID].GroupedConnectivity.GroupedLines,
						newCacheGroupedElements(), true)
			}
		case AllSubnets:
			if subnetsConn[vpcUID] != nil {
				subnetsConn[vpcUID].GroupedConnectivity.GroupedLines =
					unifiedGroupedConnLines(subnetsConn[vpcUID].GroupedConnectivity.GroupedLines,
						newCacheGroupedElements(), true)
			}
		}
	}
}

// cacheGroupedElements functionality
// ///////////////////////////////////////////////////////
// 1. functionality related to cachedGrouped.groupedEndpointsElemsMap
// gets pointer of an element semantically equiv to grouped in cachedGrouped.groupedEndpointsElemsMap
// if exists, nil otherwise
func (cachedGrouped *cacheGroupedElements) getExistEndpointElemFromCache(
	grouped *groupedEndpointsElems) *groupedEndpointsElems {
	// since the endpoints (vsis/subnets) are sorted before printed, grouped.Name() will be identical
	// to equiv groupedEndpointsElems
	if existingGrouped, ok := cachedGrouped.groupedEndpointsElemsMap[grouped.Name()]; ok {
		return existingGrouped
	}
	return nil
}

// gets pointer of an element semantically equiv to grouped in cachedGrouped.groupedEndpointsElemsMap
// if does not exist, sets the input into the cache
func (cachedGrouped *cacheGroupedElements) getAndSetEndpointElemFromCache(
	groupedElem *groupedEndpointsElems) *groupedEndpointsElems {
	existing := cachedGrouped.getExistEndpointElemFromCache(groupedElem)
	if existing != nil {
		return existing
	}
	cachedGrouped.setEndpointElemFromCache(groupedElem)
	return &groupedElem
}

// sets pointer of an element to cachedGrouped.groupedEndpointsElemsMap
func (cachedGrouped *cacheGroupedElements) setEndpointElemFromCache(
	groupedElem *groupedEndpointsElems) {
	cachedGrouped.groupedEndpointsElemsMap[groupedElem.Name()] = groupedElem
}

// 2. Similar to the above, functionality related to cachedGrouped.groupedExternalNodesMap
// gets pointer of an element semantically equiv to grouped in cachedGrouped.groupedExternalNodesMap
// if exists, nil otherwise
func (cachedGrouped *cacheGroupedElements) getExistGroupedExternalFromCache(
	grouped groupedExternalNodes) *groupedExternalNodes {
	if existingGrouped, ok := cachedGrouped.groupedExternalNodesMap[grouped.Name()]; ok {
		return existingGrouped
	}
	return nil
}

func (cachedGrouped *cacheGroupedElements) setGroupedExternalFromCache(
	groupedExternal groupedExternalNodes) {
	cachedGrouped.groupedExternalNodesMap[groupedExternal.Name()] = &groupedExternal
}

func (cachedGrouped *cacheGroupedElements) getAndSetGroupedExternalFromCache(
	groupedExternal groupedExternalNodes) *groupedExternalNodes {
	existing := cachedGrouped.getExistGroupedExternalFromCache(groupedExternal)
	if existing != nil {
		return existing
	}
	cachedGrouped.setGroupedExternalFromCache(groupedExternal)
	return &groupedExternal
}
