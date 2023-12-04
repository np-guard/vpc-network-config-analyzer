package vpcmodel

import "github.com/np-guard/vpc-network-config-analyzer/pkg/common"

type GeneralConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*common.ConnectionSet

func (connectivityMap GeneralConnectivityMap) updateAllowedConnsMap(src, dst VPCResourceIntf, conn *common.ConnectionSet) {
	if _, ok := connectivityMap[src]; !ok {
		connectivityMap[src] = map[VPCResourceIntf]*common.ConnectionSet{}
	}
	connectivityMap[src][dst] = conn
}
