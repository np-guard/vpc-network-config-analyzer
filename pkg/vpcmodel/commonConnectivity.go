/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"github.com/np-guard/models/pkg/connection"
)

// GeneralResponsiveConnectivityMap describes connectivity
type GeneralResponsiveConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*detailedConn

type GeneralConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*connection.Set

func (allowConnCombined GeneralConnectivityMap) updateAllowedConnsMap(src, dst VPCResourceIntf, conn *connection.Set) {
	if _, ok := allowConnCombined[src]; !ok {
		allowConnCombined[src] = map[VPCResourceIntf]*connection.Set{}
	}
	allowConnCombined[src][dst] = conn
}

func (statefulConnMap GeneralResponsiveConnectivityMap) updateMap(connectivityMap2 GeneralResponsiveConnectivityMap) {
	for src, nodeConns := range connectivityMap2 {
		for dst, conns := range nodeConns {
			statefulConnMap.updateAllowedStatefulConnsMap(src, dst, conns)
		}
	}
}
func (statefulConnMap GeneralResponsiveConnectivityMap) copy() GeneralResponsiveConnectivityMap {
	newConnectivityMap := GeneralResponsiveConnectivityMap{}
	newConnectivityMap.updateMap(statefulConnMap)
	return newConnectivityMap
}

// it is assumed that the components of detailedConn are legal connection.Set, namely not nil
func (statefulConnMap GeneralResponsiveConnectivityMap) updateAllowedStatefulConnsMap(src,
	dst VPCResourceIntf, conn *detailedConn) {
	if _, ok := statefulConnMap[src]; !ok {
		statefulConnMap[src] = map[VPCResourceIntf]*detailedConn{}
	}
	statefulConnMap[src][dst] = conn
}
