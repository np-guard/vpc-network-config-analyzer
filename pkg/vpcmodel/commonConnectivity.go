package vpcmodel

import "github.com/np-guard/vpc-network-config-analyzer/pkg/common"

type GeneralConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*common.ConnectionSet

func (connectivityMap GeneralConnectivityMap) updateAllowedConnsMap(src, dst VPCResourceIntf, conn *common.ConnectionSet) {
	if _, ok := connectivityMap[src]; !ok {
		connectivityMap[src] = map[VPCResourceIntf]*common.ConnectionSet{}
	}
	connectivityMap[src][dst] = conn
}

// getRoutingResource: gets the routing resource and its conn; currently the conn is either all or none
// node is associated with either a pgw or a fip;
// if the relevant network interface has both the parser will keep only the fip.
func (c *VPCConfig) getRoutingResource(src, dst Node) (RoutingResource, *common.ConnectionSet) {
	for _, router := range c.RoutingResources {
		routerConnRes := router.AllowedConnectivity(src, dst)
		if !routerConnRes.IsEmpty() { // connection is allowed through router resource
			return router, routerConnRes
		}
	}
	return nil, NoConns()
}
