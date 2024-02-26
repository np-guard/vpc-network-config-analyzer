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
			VPCConnectivity := nodesConn[vpcName]
			VPCConnectivity.GroupedConnectivity.GroupedLines =
				unifiedGroupedConnLines(VPCConnectivity.GroupedConnectivity.GroupedLines,
					groupedEndpointsElemsMap, groupedExternalNodesMap, true)
		case AllSubnets:
			subnetConnectivity := subnetsConn[vpcName]
			subnetConnectivity.GroupedConnectivity.GroupedLines =
				unifiedGroupedConnLines(subnetConnectivity.GroupedConnectivity.GroupedLines,
					groupedEndpointsElemsMap, groupedExternalNodesMap, true)
		}
	}
}
