package vpcmodel

// unifyMultiVPC unifies multi-vpc graph for endpoints and subnets connectivity s.t.
// each node appears once across multi-vpcs this is relevant only for DRAWIO and ARCHDRAWIO
// in which there is a multivpc presentation
// todo: this is actually required only for drawio, which is not accessible from the current context
func unifyMultiVPC(config1 map[string]*VPCConfig, nodesConn map[string]*VPCConnectivity,
	subnetsConn map[string]*VPCsubnetConnectivity, uc OutputUseCase) {
	groupedEndpointsElemsMap := map[string]*groupedEndpointsElems{}
	groupedExternalNodesMap := map[string]*groupedExternalNodes{}
	for vpcName := range config1 {
		switch uc {
		case AllEndpoints:
			nodesConn[vpcName].GroupedConnectivity.GroupedLines =
				unifiedGroupedConnLines(nodesConn[vpcName].GroupedConnectivity.GroupedLines,
					groupedEndpointsElemsMap, groupedExternalNodesMap, true)
		case AllSubnets:
			subnetsConn[vpcName].GroupedConnectivity.GroupedLines =
				unifiedGroupedConnLines(subnetsConn[vpcName].GroupedConnectivity.GroupedLines,
					groupedEndpointsElemsMap, groupedExternalNodesMap, true)
		}
	}
}
