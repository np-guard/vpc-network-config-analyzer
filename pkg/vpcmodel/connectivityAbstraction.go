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

// the abstraction steps are:
// 1. partition the connectivity to four disjoint groups as follows:
//      otherToOther:     connections of   <node not in the nodeSet>  ->  <node not in the nodeSet>
//      nodeSetToNodeSet: connections of   <node     in the nodeSet>  ->  <node     in the nodeSet>
//      otherFromNodeSet: connections of   <node     in the nodeSet>  ->  <node not in the nodeSet>
//      otherToNodeSet:   connections of   <node not in the nodeSet>  ->  <node     in the nodeSet>
// 2. for the last three groups, we verify that the abstraction assumption holds
//     todo: this check is not complete in code yet, and currently we ignore its result
// 3. we do the abstraction (for this PR, even if the abstraction assumption does not hold):
//    the connectivity of n->NS is union of all of n->n1, n->n2, n->n3
//    todo: what to do if the abstraction assumption does not hold?

func nodeSetConnectivityAbstraction(nodesConn GeneralConnectivityMap, nodeSet NodeSet) GeneralConnectivityMap {
	otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet := partitionConnectivityByNodeSet(nodesConn, nodeSet)
	// checkConnectivityAbstractionValidity(otherFromNodeSet, nodeSet, false)
	// checkConnectivityAbstractionValidity(otherToNodeSet, nodeSet, true)
	// checkConnectivityAbstractionValidity(nodeSetToNodeSet, nodeSet, true)
	return mergeConnectivityWithNodeSetAbstraction(otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet, nodeSet)
}

// partitionConnectivityByNodeSet() par the connectivity to the four groups
// each group is kept as GeneralConnectivityMap.
// usually, GeneralConnectivityMap is a map form src to dst.
// however, the third group is hold as a map from dst to src (and therefore called otherFromNodeSet and not nodeSetToOther)
// see the reason on mergeConnectivityWithNodeSetAbstraction()

func partitionConnectivityByNodeSet(nodesConn GeneralConnectivityMap, nodeSet NodeSet) (
	otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet GeneralConnectivityMap) {
	otherToOther = GeneralConnectivityMap{}
	nodeSetToNodeSet = GeneralConnectivityMap{}
	otherFromNodeSet = GeneralConnectivityMap{}
	otherToNodeSet = GeneralConnectivityMap{}
	for src, nodeConns := range nodesConn {
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
				otherToNodeSet.updateAllowedConnsMap(src, dst, conns.Copy())
			}
		}
	}
	return otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet
}

// checkConnectivityAbstractionValidity() checks if the abstraction assumption holds
// it does it on each group separately.
// for now it creates a string
// todo: - how to report this string? what format?
// for now, No need to CR it, we do not do anything with the result

// func checkConnectivityAbstractionValidity(connMap GeneralConnectivityMap, nodeSet NodeSet, isIngress bool) {
// 	res := ""
// 	for node1, nodeConns := range connMap {
// 		allConns := map[string][]VPCResourceIntf{}
// 		for node2, conn := range nodeConns {
// 			allConns[conn.String()] = append(allConns[conn.String()], node2)
// 		}
// 		if len(allConns) > 1 || len(nodeConns) != len(nodeSet.Nodes()) {
// 			directionAdjective := map[bool]string{false: "from", true: "to"}[isIngress]
// 			res += fmt.Sprintf("node %s has different access %s %s:\n", node1.Name(), directionAdjective, nodeSet.Name())
// 			if len(nodeConns) != len(nodeSet.Nodes()) {
// 				res += fmt.Sprintf("    it has no access %s ", directionAdjective)
// 				for _, node2 := range nodeSet.Nodes() {
// 					if _, ok := nodeConns[node2]; !ok {
// 						res += fmt.Sprintf("%s, ", node2.Name())
// 					}
// 				}
// 				res += "\n"
// 			}
// 			for conn, nodes := range allConns {
// 				res += "    "
// 				if isIngress {
// 					res += fmt.Sprintf("%s -> ", node1.Name())
// 				}
// 				for _, n := range nodes {
// 					res += fmt.Sprintf("%s,", n.Name())
// 				}
// 				if !isIngress {
// 					res += fmt.Sprintf(" -> %s", node1.Name())
// 				}
// 				res += fmt.Sprintf(" %s\n", conn)
// 			}
// 		}
// 	}
// }

// mergeConnectivityWithNodeSetAbstraction() merge the four groups, while abstracting the connections
func mergeConnectivityWithNodeSetAbstraction(
	otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet GeneralConnectivityMap,
	nodeSet NodeSet) GeneralConnectivityMap {
	// first make a copy of otherToOther, to be the result:
	res := GeneralConnectivityMap{}
	for src, nodeConns := range otherToOther {
		for dst, conns := range nodeConns {
			res.updateAllowedConnsMap(src, dst, conns)
		}
	}
	// all the connections with the nodeSet are merged to *only* one connectivity, which is the union of all separate connections:
	allConns := NoConns()
	for _, nodeConns := range nodeSetToNodeSet {
		for _, conns := range nodeConns {
			allConns = allConns.Union(conns)
		}
	}
	// adding to the result
	res.updateAllowedConnsMap(nodeSet, nodeSet, allConns)

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
		res.updateAllowedConnsMap(nodeSet, dst, allConns)
	}

	// all connection from a node to the nodeSet, are union and added to the result:
	for src, nodeConns := range otherToNodeSet {
		allConns := NoConns()
		for _, conns := range nodeConns {
			allConns = allConns.Union(conns)
		}
		res.updateAllowedConnsMap(src, nodeSet, allConns)
	}

	return res
}
