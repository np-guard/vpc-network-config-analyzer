package vpcmodel

// unifyMultiVPC unifies multi-vpc graph for endpoints and subnets connectivity s.t.
// each node appears once across multi-vpcs this is relevant only for DRAWIO and ARCHDRAWIO
// in which there is a multivpc presentation
// todo: this is actually required only for drawio, which is not accessible from the current context
func unifyMultiVPC(config1 map[string]*VPCConfig, nodesConn map[string]*VPCConnectivity,
	subnetsConn map[string]*VPCsubnetConnectivity) {
	groupedEndpointsElemsMap := map[string]*groupedEndpointsElems{}
	groupedExternalNodesMap := map[string]*groupedExternalNodes{}
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
}
