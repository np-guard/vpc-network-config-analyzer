/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"github.com/np-guard/models/pkg/connection"
)

// GeneralConnectivityMap describes basic connectivity of the given network;
// for each ordered couple of VPCResourceIntf <src, dst> that have connection between src to dst
// it lists the protocols and ports for which the connection <src, dst> is enabled
type GeneralConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*connection.Set

// GeneralResponsiveConnectivityMap describes connectivity similarly to GeneralConnectivityMap;
// only here the describes connection includes respond details,namely in what cases a TCP respond is enabled
type GeneralResponsiveConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*detailedConn

func (allowConnCombined GeneralConnectivityMap) updateAllowedConnsMap(src, dst VPCResourceIntf, conn *connection.Set) {
	if _, ok := allowConnCombined[src]; !ok {
		allowConnCombined[src] = map[VPCResourceIntf]*connection.Set{}
	}
	allowConnCombined[src][dst] = conn
}

func (responsiveConnMap GeneralResponsiveConnectivityMap) updateMap(connectivityMap2 GeneralResponsiveConnectivityMap) {
	for src, nodeConns := range connectivityMap2 {
		for dst, conns := range nodeConns {
			responsiveConnMap.updateAllowedResponsiveConnsMap(src, dst, conns)
		}
	}
}
func (responsiveConnMap GeneralResponsiveConnectivityMap) copy() GeneralResponsiveConnectivityMap {
	newConnectivityMap := GeneralResponsiveConnectivityMap{}
	newConnectivityMap.updateMap(responsiveConnMap)
	return newConnectivityMap
}

// it is assumed that the components of detailedConn are legal connection.Set, namely not nil
func (responsiveConnMap GeneralResponsiveConnectivityMap) updateAllowedResponsiveConnsMap(src,
	dst VPCResourceIntf, conn *detailedConn) {
	if _, ok := responsiveConnMap[src]; !ok {
		responsiveConnMap[src] = map[VPCResourceIntf]*detailedConn{}
	}
	responsiveConnMap[src][dst] = conn
}
