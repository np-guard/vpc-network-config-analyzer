/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"slices"
)

// given a nodeSet NS[n0, n1, n2, n3...]
// we assume the "abstraction assumption":
// for every node n,  a connection  n->n0 implies the connections n->n1, n->n2, n->n3 ...
// the abstraction replaces the above n->ni connections with the single connection: n->NS.
// The same abstraction is done in the other direction
// when one of actual connections is missing (e.g. n -> n1 exists but  n->n2 does not) the "abstraction assumption" does not hold.
// these connections are called "missing connections"

// the abstraction steps are:
// 1. partition the connectivity to four disjoint groups as follows:
//      otherToOther:     connections of   <node not in the nodeSet>  ->  <node not in the nodeSet>
//      nodeSetToNodeSet: connections of   <node     in the nodeSet>  ->  <node     in the nodeSet>
//      otherFromNodeSet: connections of   <node     in the nodeSet>  ->  <node not in the nodeSet>
//      otherToNodeSet:   connections of   <node not in the nodeSet>  ->  <node     in the nodeSet>
// 2. we do the abstraction on the last three groups:
//    the connectivity of n->NS is union of all of n->n1, n->n2, n->n3
// 3. for the last three groups, we collect the missing connections.
// 4. we add the 4th group to connectivity

// NodeSetAbstraction abstract nodesets, one after the other
type NodeSetAbstraction struct {
	// abstractedConnectivity holds the abstracted connectivity that reflated after the last nodeSet abstraction
	abstractedConnectivity GeneralResponsiveConnectivityMap
}

func newNodeSetAbstraction(nodesConn GeneralResponsiveConnectivityMap) *NodeSetAbstraction {
	return &NodeSetAbstraction{nodesConn.copy()}
}

func (nsa *NodeSetAbstraction) abstractNodeSet(nodeSet NodeSet) *AbstractionInfo {
	// partition the connectivity to four groups:
	otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet := nsa.partitionConnectivityByNodeSet(nodeSet)
	// merge the three last groups:
	mergedConnectivity := nsa.mergeConnectivityWithNodeSetAbstraction(nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet, nodeSet)
	// collect the abstracted information of the nodeSet:
	abstractionInfo := nsa.nodeSetAbstractionInformation(mergedConnectivity, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet, nodeSet)
	// add the fourth group
	mergedConnectivity.updateMap(otherToOther)
	// update the connectivity
	nsa.abstractedConnectivity = mergedConnectivity
	return abstractionInfo
}

// partitionConnectivityByNodeSet() returns partitions from the connectivity to the four groups
// each group is kept as GeneralConnectivityMap.
// usually, GeneralConnectivityMap is a map form src to dst.
// however, the third group is hold as a map from dst to src (and therefore called otherFromNodeSet and not nodeSetToOther)
// see the reason on mergeConnectivityWithNodeSetAbstraction()

func (nsa *NodeSetAbstraction) partitionConnectivityByNodeSet(nodeSet NodeSet) (
	otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet GeneralResponsiveConnectivityMap) {
	otherToOther = GeneralResponsiveConnectivityMap{}
	nodeSetToNodeSet = GeneralResponsiveConnectivityMap{}
	otherFromNodeSet = GeneralResponsiveConnectivityMap{}
	otherToNodeSet = GeneralResponsiveConnectivityMap{}
	for src, nodeConns := range nsa.abstractedConnectivity {
		for dst, conns := range nodeConns {
			srcNode, srcIsNode := src.(Node)
			dstNode, dstIsNode := dst.(Node)
			srcInSet := srcIsNode && slices.Contains(nodeSet.Nodes(), srcNode)
			dstInSet := dstIsNode && slices.Contains(nodeSet.Nodes(), dstNode)
			switch {
			case !srcInSet && !dstInSet:
				otherToOther.updateAllowedResponsiveConnsMap(src, dst, conns)
			case srcInSet && dstInSet:
				nodeSetToNodeSet.updateAllowedResponsiveConnsMap(src, dst, conns)
			case srcInSet && !dstInSet:
				otherFromNodeSet.updateAllowedResponsiveConnsMap(dst, src, conns)
			case !srcInSet && dstInSet:
				otherToNodeSet.updateAllowedResponsiveConnsMap(src, dst, conns)
			}
		}
	}
	return otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet
}

// mergeConnectivityWithNodeSetAbstraction() merge the three last groups, while abstracting the connections
func (nsa *NodeSetAbstraction) mergeConnectivityWithNodeSetAbstraction(
	nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet GeneralResponsiveConnectivityMap,
	nodeSet NodeSet) GeneralResponsiveConnectivityMap {
	unionConns := func(conn *detailedConn, conns map[VPCResourceIntf]*detailedConn) *detailedConn {
		for _, c := range conns {
			conn = conn.union(c)
		}
		return conn
	}
	// all the connections with the nodeSet are merged to *only* one connectivity, which is the union of all separate connections:
	mergedConnectivity := GeneralResponsiveConnectivityMap{}
	allConns := emptyDetailedConn()
	for _, nodeConns := range nodeSetToNodeSet {
		allConns = unionConns(allConns, nodeConns)
	}
	// adding to the result
	mergedConnectivity.updateAllowedResponsiveConnsMap(nodeSet, nodeSet, allConns)

	// all connection from the nodeSet to a node, are merged and added to the result:
	// please note: we need to handle separately each node that is not in the NodeSet,
	// therefore, we want to have a loop on every node that is not in the nodeSet.
	// so, the outer loop should run over the nodes not in the nodeSet.
	// hence, this group is from dst to src.
	for dst, nodeConns := range otherFromNodeSet {
		allConns = unionConns(emptyDetailedConn(), nodeConns)
		mergedConnectivity.updateAllowedResponsiveConnsMap(nodeSet, dst, allConns)
	}

	// all connection from a node to the nodeSet, are union and added to the result:
	for src, nodeConns := range otherToNodeSet {
		allConns = unionConns(emptyDetailedConn(), nodeConns)
		mergedConnectivity.updateAllowedResponsiveConnsMap(src, nodeSet, allConns)
	}
	return mergedConnectivity
}

// nodeSetAbstractionInformation() collects abstraction information of the nodeSet.
// for now, it collects the "missing connections" (as described above) info.
func (nsa *NodeSetAbstraction) nodeSetAbstractionInformation(mergedConnectivity,
	nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet GeneralResponsiveConnectivityMap,
	nodeSet NodeSet) *AbstractionInfo {
	abstractionInfo := &AbstractionInfo{}
	abstractionInfo.missingEgressConnections = nsa.missingConnections(otherFromNodeSet, mergedConnectivity, nodeSet, fromNodeSet)
	abstractionInfo.missingIngressConnections = nsa.missingConnections(otherToNodeSet, mergedConnectivity, nodeSet, toNodeSet)
	abstractionInfo.missingIngressConnections.updateMap(nsa.missingConnections(nodeSetToNodeSet, mergedConnectivity, nodeSet, inNodeSet))
	return abstractionInfo
}

type groupDirection int

const (
	inNodeSet = iota
	fromNodeSet
	toNodeSet
)

// missingConnections() is called on each of the last three groups.
// it looks for "missing connections" -  connections that do not exist in the group, but are reflated in the mergedConnMap
func (nsa *NodeSetAbstraction) missingConnections(connMap, mergedConnMap GeneralResponsiveConnectivityMap,
	nodeSet NodeSet, groupName groupDirection) GeneralResponsiveConnectivityMap {
	missingConnection := GeneralResponsiveConnectivityMap{}
	for node1, conns := range connMap {
		// here we iterate over the nodes in the nodeSet, and not over the conns, because we can not know if conns holds the nodes:
		for _, node2 := range nodeSet.Nodes() {
			var nodeConnection, mergedConnection *detailedConn
			if nodeConnection = conns[node2]; nodeConnection == nil {
				nodeConnection = emptyDetailedConn()
			}
			switch groupName {
			case inNodeSet:
				mergedConnection = mergedConnMap[nodeSet][nodeSet]
			case toNodeSet:
				mergedConnection = mergedConnMap[node1][nodeSet]
			case fromNodeSet:
				mergedConnection = mergedConnMap[nodeSet][node1]
			}
			if !nodeConnection.equal(mergedConnection) {
				missingConn := mergedConnection.subtract(nodeConnection)
				missingConnection.updateAllowedResponsiveConnsMap(node1, node2, missingConn)
			}
		}
	}
	return missingConnection
}

// AbstractionInfo is the abstraction information of one nodeSet
type AbstractionInfo struct {
	// missingIngressConnections - the ingress connections that are missing for the assumption to hold:
	// (all connections of the form: <any node> -> <node in the node set>)
	missingIngressConnections GeneralResponsiveConnectivityMap
	// missingEgressConnections - the egress connections that are missing for the assumption to hold:
	// (all connections of the form: <node in the node set> -> <any node>)
	missingEgressConnections GeneralResponsiveConnectivityMap
}

// hasMissingConnection() checks is one of the resources has missing connection
func (aInfo *AbstractionInfo) hasMissingConnection(resources []VPCResourceIntf, isIngress bool) bool {
	missingConnections := aInfo.missingEgressConnections
	if isIngress {
		missingConnections = aInfo.missingIngressConnections
	}
	for _, resource := range resources {
		if _, ok := missingConnections[resource]; ok {
			return true
		}
	}
	return false
}
