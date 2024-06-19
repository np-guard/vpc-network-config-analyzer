/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package vpcmodel

import (
	"testing"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/netp"
	"github.com/stretchr/testify/require"
)

func createNodes() (NodeSet, []VPCResourceIntf) {
	node0, _ := newExternalNodeForCidr("0.0.0.0/32")
	node1, _ := newExternalNodeForCidr("0.0.0.1/32")
	node2, _ := newExternalNodeForCidr("0.0.0.2/32")
	node3, _ := newExternalNodeForCidr("0.0.0.3/32")
	nodeSet := mockSubnet{name: "nodeSet", nodes: []Node{node0, node1, node2, node3}}

	outNode0, _ := newExternalNodeForCidr("0.0.1.0/32")
	outNode1, _ := newExternalNodeForCidr("0.0.1.1/32")
	outNode2, _ := newExternalNodeForCidr("0.0.1.2/32")

	outNodes := []VPCResourceIntf{outNode0, outNode1, outNode2}
	return &nodeSet, outNodes
}
func emptyGeneralResponsiveConnectivityMap(nodeSet NodeSet, outNodes []VPCResourceIntf) GeneralResponsiveConnectivityMap {
	nodesConn := GeneralResponsiveConnectivityMap{}
	for _, n1 := range nodeSet.Nodes() {
		for _, n2 := range nodeSet.Nodes() {
			if n1 != n2 {
				nodesConn.updateAllowedResponsiveConnsMap(n1, n2, emptyDetailedConn())
				nodesConn.updateAllowedResponsiveConnsMap(n2, n1, emptyDetailedConn())
			}
		}
	}
	for _, n1 := range nodeSet.Nodes() {
		for _, n2 := range outNodes {
			nodesConn.updateAllowedResponsiveConnsMap(n1, n2, emptyDetailedConn())
			nodesConn.updateAllowedResponsiveConnsMap(n2, n1, emptyDetailedConn())
		}
	}
	for _, n1 := range outNodes {
		for _, n2 := range outNodes {
			if n1 != n2 {
				nodesConn.updateAllowedResponsiveConnsMap(n1, n2, emptyDetailedConn())
				nodesConn.updateAllowedResponsiveConnsMap(n2, n1, emptyDetailedConn())
			}
		}
	}
	return nodesConn
}

func createConnections() []*detailedConn {
	return []*detailedConn{
		detailedConnForAllRsp(),
		detailedConnForResponsive(connection.TCPorUDPConnection(netp.ProtocolStringTCP, 10, 100, 443, 443)),
		emptyDetailedConn(),
	}
}

func createFullConn(nodeSet NodeSet, outNodes []VPCResourceIntf, conn *detailedConn) GeneralResponsiveConnectivityMap {
	nodesConn := emptyGeneralResponsiveConnectivityMap(nodeSet, outNodes)
	for _, n := range nodeSet.Nodes() {
		for _, on := range outNodes {
			nodesConn.updateAllowedResponsiveConnsMap(n, on, conn)
			nodesConn.updateAllowedResponsiveConnsMap(on, n, conn)
		}
	}
	return nodesConn
}
func checkFullConn(nodeSet NodeSet, outNodes []VPCResourceIntf, conn *detailedConn,
	aConn GeneralResponsiveConnectivityMap, info *AbstractionInfo,
	t *testing.T) {
	require.Equal(t, len(aConn), len(outNodes)+1)
	require.False(t, info.hasMissingConnection(outNodes, false))
	require.False(t, info.hasMissingConnection(outNodes, true))
	for _, on := range outNodes {
		require.True(t, conn.equal(aConn[nodeSet][on]))
		require.True(t, conn.equal(aConn[on][nodeSet]))
		require.Equal(t, len(aConn[on]), len(outNodes))
	}
}

func TestSimpleAbstraction(t *testing.T) {
	nodeSet, outNodes := createNodes()
	conns := createConnections()
	for _, conn := range conns {
		nodesConn := createFullConn(nodeSet, outNodes, conn)
		nodeSetAbstraction := newNodeSetAbstraction(nodesConn)
		info := nodeSetAbstraction.abstractNodeSet(nodeSet)
		aConn := nodeSetAbstraction.abstractedConnectivity
		checkFullConn(nodeSet, outNodes, conn, aConn, info, t)
	}
}

///////////////////////////////////////////////////////////////////////////////

func createMissingConn(nodeSet NodeSet, outNodes []VPCResourceIntf, conn, subConn *detailedConn) GeneralResponsiveConnectivityMap {
	nodesConn := emptyGeneralResponsiveConnectivityMap(nodeSet, outNodes)
	for i1, n := range nodeSet.Nodes() {
		for i2, on := range outNodes {
			conn := conn
			// for i2 == 1, we set one subConn. for i2 == 2, we set all connections to subConn:
			if i2 == 1 && i1 == 0 || i2 == 2 {
				conn = subConn
			}
			nodesConn.updateAllowedResponsiveConnsMap(n, on, conn)
			nodesConn.updateAllowedResponsiveConnsMap(on, n, conn)
		}
	}
	return nodesConn
}
func checkMissingConn(nodeSet NodeSet, outNodes []VPCResourceIntf, conn, subConn *detailedConn,
	aConn GeneralResponsiveConnectivityMap, info *AbstractionInfo,
	t *testing.T) {

	require.Equal(t, len(aConn), len(outNodes)+1)
	require.False(t, info.hasMissingConnection(outNodes[0:1], false))
	require.False(t, info.hasMissingConnection(outNodes[0:1], true))
	require.True(t, info.hasMissingConnection(outNodes[1:2], false))
	require.True(t, info.hasMissingConnection(outNodes[1:2], true))
	require.True(t, info.hasMissingConnection(outNodes[1:3], false))
	require.True(t, info.hasMissingConnection(outNodes[1:3], true))
	require.False(t, info.hasMissingConnection(outNodes[2:3], false))
	require.False(t, info.hasMissingConnection(outNodes[2:3], true))

	require.Equal(t, len(aConn[nodeSet]), len(outNodes)+1)
	for _, on := range outNodes[0:2] {
		require.True(t, conn.equal(aConn[nodeSet][on]))
		require.True(t, conn.equal(aConn[on][nodeSet]))
		require.Equal(t, len(aConn[on]), len(outNodes))
	}
	require.True(t, subConn.equal(aConn[nodeSet][outNodes[2]]))
	require.True(t, subConn.equal(aConn[outNodes[2]][nodeSet]))
	require.Equal(t, len(aConn[outNodes[2]]), len(outNodes))

	require.True(t, conn.subtract(subConn).equal(info.missingEgressConnections[outNodes[1]][nodeSet.Nodes()[0]]))
	require.True(t, conn.subtract(subConn).equal(info.missingIngressConnections[outNodes[1]][nodeSet.Nodes()[0]]))
}

func checkMissingAbstractionConns(conn, subConn *detailedConn, t *testing.T) {
	nodeSet, outNodes := createNodes()
	nodesConn := createMissingConn(nodeSet, outNodes, conn, subConn)
	nodeSetAbstraction := newNodeSetAbstraction(nodesConn)
	info := nodeSetAbstraction.abstractNodeSet(nodeSet)
	aConn := nodeSetAbstraction.abstractedConnectivity
	checkMissingConn(nodeSet, outNodes, conn, subConn, aConn, info, t)
}

func TestMissingAbstraction(t *testing.T) {
	conns := createConnections()
	checkMissingAbstractionConns(conns[0], conns[1], t)
	checkMissingAbstractionConns(conns[0], conns[2], t)
	checkMissingAbstractionConns(conns[1], conns[2], t)
}
