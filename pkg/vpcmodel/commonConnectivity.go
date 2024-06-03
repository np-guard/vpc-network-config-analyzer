/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import "github.com/np-guard/models/pkg/connection"

type GeneralConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*connection.Set

func (connectivityMap GeneralConnectivityMap) updateAllowedConnsMap(src, dst VPCResourceIntf, conn *connection.Set) {
	if _, ok := connectivityMap[src]; !ok {
		connectivityMap[src] = map[VPCResourceIntf]*connection.Set{}
	}
	connectivityMap[src][dst] = conn
}

func (connectivityMap GeneralConnectivityMap) updateMap(connectivityMap2 GeneralConnectivityMap) {
	for src, nodeConns := range connectivityMap2 {
		for dst, conns := range nodeConns {
			connectivityMap.updateAllowedConnsMap(src, dst, conns)
		}
	}
}
func (connectivityMap GeneralConnectivityMap) copy() GeneralConnectivityMap {
	newConnectivityMap := GeneralConnectivityMap{}
	newConnectivityMap.updateMap(connectivityMap)
	return newConnectivityMap
}
