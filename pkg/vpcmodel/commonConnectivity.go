/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
)

func newTCPConn(srcMinP, srcMaxP, dstMinP, dstMaxP int64) *netset.TransportSet {
	return netset.NewTCPorUDPTransport(netp.ProtocolStringTCP, srcMinP, srcMaxP, dstMinP, dstMaxP)
}

func newUDPConn(srcMinP, srcMaxP, dstMinP, dstMaxP int64) *netset.TransportSet {
	return netset.NewTCPorUDPTransport(netp.ProtocolStringUDP, srcMinP, srcMaxP, dstMinP, dstMaxP)
}

func newICMPconn() *netset.TransportSet {
	return netset.AllICMPTransport()
}

func newTCPUDPSet(p netp.ProtocolString) *netset.TransportSet {
	return netset.NewTCPorUDPTransport(p,
		netp.MinPort, netp.MaxPort,
		netp.MinPort, netp.MaxPort)
}

func allTCPconn() *netset.TransportSet {
	return newTCPConn(netp.MinPort, netp.MaxPort,
		netp.MinPort, netp.MaxPort)
}

// PartitionTCPNonTCP given a connection returns its TCP and non-TCP sub-connections
func partitionTCPNonTCP(conn *netset.TransportSet) (tcp, nonTCP *netset.TransportSet) {
	tcpFractionOfConn := allTCPconn().Intersect(conn)
	nonTCPFractionOfConn := conn.Subtract(tcpFractionOfConn)
	return tcpFractionOfConn, nonTCPFractionOfConn
}

// GeneralConnectivityMap describes basic connectivity of the given network;
// for each ordered couple of VPCResourceIntf <src, dst> that have connection between src to dst
// it lists the protocols and ports for which the connection <src, dst> is enabled
type GeneralConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*netset.TransportSet

// GeneralResponsiveConnectivityMap describes connectivity similarly to GeneralConnectivityMap;
// only here the describes connection includes respond details, namely in what cases a TCP respond is enabled
type GeneralResponsiveConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*detailedConn

func (allowConnCombined GeneralConnectivityMap) updateAllowedConnsMap(src, dst VPCResourceIntf, conn *netset.TransportSet) {
	if _, ok := allowConnCombined[src]; !ok {
		allowConnCombined[src] = map[VPCResourceIntf]*netset.TransportSet{}
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

// it is assumed that the components of detailedConn are legal netset.TransportSet, namely not nil
func (responsiveConnMap GeneralResponsiveConnectivityMap) updateAllowedResponsiveConnsMap(src,
	dst VPCResourceIntf, conn *detailedConn) {
	if _, ok := responsiveConnMap[src]; !ok {
		responsiveConnMap[src] = map[VPCResourceIntf]*detailedConn{}
	}
	responsiveConnMap[src][dst] = conn
}
