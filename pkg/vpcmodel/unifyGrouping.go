package vpcmodel

type cacheGroupedElements struct {
	groupedEndpointsElemsMap map[string]*groupedEndpointsElems
	groupedExternalNodesMap  map[string]*groupedExternalNodes
}

func initCacheGroupedElem() *cacheGroupedElements {
	return &cacheGroupedElements{
		map[string]*groupedEndpointsElems{},
		map[string]*groupedExternalNodes{},
	}
}

// unifyMultiVPC unifies multi-vpc graph for endpoints and subnets connectivity s.t.
// each node appears once across multi-vpcs this is relevant only for DRAWIO
// in which there is a multivpc presentation
func unifyMultiVPC(config1 map[string]*VPCConfig, nodesConn map[string]*VPCConnectivity,
	subnetsConn map[string]*VPCsubnetConnectivity, uc OutputUseCase) {
	for vpcUID := range config1 {
		switch uc {
		case AllEndpoints:
			nodesConn[vpcUID].GroupedConnectivity.GroupedLines =
				unifiedGroupedConnLines(nodesConn[vpcUID].GroupedConnectivity.GroupedLines,
					initCacheGroupedElem(), true)
		case AllSubnets:
			subnetsConn[vpcUID].GroupedConnectivity.GroupedLines =
				unifiedGroupedConnLines(subnetsConn[vpcUID].GroupedConnectivity.GroupedLines,
					initCacheGroupedElem(), true)
		}
	}
}
