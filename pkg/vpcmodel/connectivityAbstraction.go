/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"slices"

	"github.com/np-guard/models/pkg/connection"
)

// given a nodeSet NS[n0, n1, n2, n3...]
// we assume the "abstraction assumption":
// for every node n,  a connection  n->n0 implies the connections n->n1, n->n2, n->n3 ...
// the abstraction replaces the above n->ni connections with the single connection: n->NS.
// The same abstraction is done in the other direction

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

// NodeSetAbstraction holds the info of the abstraction
type NodeSetAbstraction struct {
	abstractedConnectivity    GeneralConnectivityMap // the abstracted connectivity
	missingIngressConnections GeneralConnectivityMap // the ingress connections that are missing for the assumption to hold
	missingEgressConnections  GeneralConnectivityMap // the egress connections that are missing for the assumption to hold
}

func newNodeSetAbstraction(nodesConn GeneralConnectivityMap) *NodeSetAbstraction {

	 return  &NodeSetAbstraction{nodesConn.copy(), GeneralConnectivityMap{}, GeneralConnectivityMap{}}
}

func (ai *NodeSetAbstraction) nodeSetConnectivityAbstraction(nodeSet NodeSet) {
	// partition the connectivity to four groups:
	otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet := ai.partitionConnectivityByNodeSet(nodeSet)
	// merge the three last groups:
	mergedConnectivity := ai.mergeConnectivityWithNodeSetAbstraction(nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet, nodeSet)
	// collect the missing connections:
	ai.abstractionMissingConnections(otherFromNodeSet, mergedConnectivity, nodeSet, false)
	ai.abstractionMissingConnections(otherToNodeSet, mergedConnectivity, nodeSet, true)
	ai.abstractionMissingConnections(nodeSetToNodeSet, mergedConnectivity, nodeSet, true)
	// add the forth group
	mergedConnectivity.addMap(otherToOther)
	// updating the connectivity
	ai.abstractedConnectivity = mergedConnectivity
}

// partitionConnectivityByNodeSet() returns partitions from the connectivity to the four groups
// each group is kept as GeneralConnectivityMap.
// usually, GeneralConnectivityMap is a map form src to dst.
// however, the third group is hold as a map from dst to src (and therefore called otherFromNodeSet and not nodeSetToOther)
// see the reason on mergeConnectivityWithNodeSetAbstraction()

func (ai *NodeSetAbstraction) partitionConnectivityByNodeSet(nodeSet NodeSet) (
	otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet GeneralConnectivityMap) {
	otherToOther = GeneralConnectivityMap{}
	nodeSetToNodeSet = GeneralConnectivityMap{}
	otherFromNodeSet = GeneralConnectivityMap{}
	otherToNodeSet = GeneralConnectivityMap{}
	for src, nodeConns := range ai.abstractedConnectivity {
		for dst, conns := range nodeConns {
			srcNode, srcIsNode := src.(Node)
			dstNode, dstIsNode := dst.(Node)
			srcInSet := srcIsNode && slices.Contains(nodeSet.Nodes(), srcNode)
			dstInSet := dstIsNode && slices.Contains(nodeSet.Nodes(), dstNode)
			switch {
			case (!srcInSet && !dstInSet) || conns.IsEmpty():
				otherToOther.updateAllowedConnsMap(src, dst, conns)
			case srcInSet && dstInSet:
				nodeSetToNodeSet.updateAllowedConnsMap(src, dst, conns)
			case srcInSet && !dstInSet:
				otherFromNodeSet.updateAllowedConnsMap(dst, src, conns)
			case !srcInSet && dstInSet:
				otherToNodeSet.updateAllowedConnsMap(src, dst, conns)
			}
		}
	}
	return otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet
}

// mergeConnectivityWithNodeSetAbstraction() merge the three last groups, while abstracting the connections
func (ai *NodeSetAbstraction) mergeConnectivityWithNodeSetAbstraction(
	nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet GeneralConnectivityMap,
	nodeSet NodeSet) GeneralConnectivityMap{
	// all the connections with the nodeSet are merged to *only* one connectivity, which is the union of all separate connections:
	mergedConnectivity := GeneralConnectivityMap{}
	allConns := NoConns()
	for _, nodeConns := range nodeSetToNodeSet {
		for _, conns := range nodeConns {
			allConns = allConns.Union(conns)
		}
	}
	// adding to the result
	mergedConnectivity.updateAllowedConnsMap(nodeSet, nodeSet, allConns)

	// all connection from the nodeSet to a node, are merged and added to the result:
	// please note: we need to handle separately each node that is not in the NodeSet,
	// therefore, we want to have a loop on every node that is not in the nodeSet.
	// so, the outer loop should run over the nodes not in the nodeSet.
	// hence, this group is from dst to src.
	for dst, nodeConns := range otherFromNodeSet {
		allConns := NoConns()
		for _, conns := range nodeConns {
			allConns = allConns.Union(conns)
		}
		mergedConnectivity.updateAllowedConnsMap(nodeSet, dst, allConns)
	}

	// all connection from a node to the nodeSet, are union and added to the result:
	for src, nodeConns := range otherToNodeSet {
		allConns := NoConns()
		for _, conns := range nodeConns {
			allConns = allConns.Union(conns)
		}
		mergedConnectivity.updateAllowedConnsMap(src, nodeSet, allConns)
	}
	return mergedConnectivity
}

func (ai *NodeSetAbstraction) missingConnections(isIngress bool) GeneralConnectivityMap {
	if isIngress {
		return ai.missingIngressConnections
	}
	return ai.missingEgressConnections
}

// abstractionMissingConnections() collects the connections that are missing for full abstraction.
// abstractionMissingConnections() is called on each of the last three groups.
// it looks for the connections that are not exist in the connMap, but reflated in the mergedConnMap
func (ai *NodeSetAbstraction) abstractionMissingConnections(connMap, mergedConnMap GeneralConnectivityMap, nodeSet NodeSet, isIngress bool) {
	for node1, conns := range connMap {
		// here we iterate over the nodes in the nodeSet, and not over the conns, because we can not know if conns holds the nodes:
		for _, node2 := range nodeSet.Nodes() {
			var nodeConnection, mergedConnection *connection.Set
			if nodeConnection = conns[node2]; nodeConnection == nil {
				nodeConnection = NoConns()
			}
			if isIngress {
				mergedConnection = mergedConnMap[node1][nodeSet]
			} else {
				mergedConnection = mergedConnMap[nodeSet][node1]
			}
			if !nodeConnection.Equal(mergedConnection) {
				missingConn := mergedConnection.Subtract(nodeConnection)
				ai.missingConnections(isIngress).updateAllowedConnsMap(node1, node2, missingConn)
			}
		}
	}
}

// hasMissingConnection() checks is one of the resources has missing connection
func (ai *NodeSetAbstraction) hasMissingConnection(resources []VPCResourceIntf, isIngress bool) bool {
	for _, resource := range resources {
		if _, ok := ai.missingConnections(isIngress)[resource]; ok {
			return true
		}
	}
	return false
}
