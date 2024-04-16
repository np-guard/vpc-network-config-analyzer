/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"fmt"
	"slices"
)

// connectivity abstraction of a nodeSet:
// consider nodeSet NS[N0, N1, N2, N3...]
// we assume that for every node N,  if we have the connection  N->N0
// then we also have the connections N->N1, N->N2, N->N3 ...
// we will call it the abstraction assumption
// so we replace all these connections with one connection: N->NS.

// the abstraction steps are:
// 1. splitting the connectivity to for groups:
//      otherToOther:     connections of   <node not in the nodeSet>  ->  <node not in the nodeSet>
//      nodeSetToNodeSet: connections of   <node     in the nodeSet>  ->  <node     in the nodeSet>
//      otherFromNodeSet: connections of   <node     in the nodeSet>  ->  <node not in the nodeSet>
//      otherToNodeSet:   connections of   <node not in the nodeSet>  ->  <node     in the nodeSet>
// 2. for the last three groups, we check the abstraction assumption holds
// 3. we do the abstraction ( for now, even if the abstraction assumption does not hold):
// the connectivity of N->NS is union of all of N->N1, N->N2, N->N3 ...
// todo: what to do if the abstraction assumption does not hold?

func nodeSetConnectivityAbstraction(nodesConn GeneralConnectivityMap, nodeSet NodeSet) GeneralConnectivityMap {
	otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet := splitConnectivityByNodeSet(nodesConn, nodeSet)
	checkConnectivityAbstractionValidity(otherFromNodeSet, nodeSet, false)
	checkConnectivityAbstractionValidity(otherToNodeSet, nodeSet, true)
	checkConnectivityAbstractionValidity(nodeSetToNodeSet, nodeSet, true)
	return mergeConnectivityWithNodeSetAbstraction(otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet, nodeSet)
}

// splitConnectivityByNodeSet() split the connectivity to the four groups
// each group is kept as GeneralConnectivityMap.
// usually, GeneralConnectivityMap is a map form src to dst.
// however, the third group is hold as a map from dst to src.

func splitConnectivityByNodeSet(nodesConn GeneralConnectivityMap, nodeSet NodeSet) (OtherToOther, nodeSetToNodeSet, OtherFromNodeSet, OtherToNodeSet GeneralConnectivityMap) {
	OtherToOther = GeneralConnectivityMap{}
	nodeSetToNodeSet = GeneralConnectivityMap{}
	OtherFromNodeSet = GeneralConnectivityMap{}
	OtherToNodeSet = GeneralConnectivityMap{}
	for src, nodeConns := range nodesConn {
		for dst, conns := range nodeConns {
			srcNode, srcIsNode := src.(Node)
			dstNode, dstIsNode := dst.(Node)
			srcInSet := srcIsNode && slices.Contains(nodeSet.Nodes(), srcNode)
			dstInSet := dstIsNode && slices.Contains(nodeSet.Nodes(), dstNode)
			switch {
			case (!srcInSet && !dstInSet) || conns.IsEmpty():
				OtherToOther.updateAllowedConnsMap(src, dst, conns)
			case srcInSet && dstInSet:
				nodeSetToNodeSet.updateAllowedConnsMap(src, dst, conns)
			case !srcInSet && dstInSet:
				OtherToNodeSet.updateAllowedConnsMap(src, dst, conns.Copy())
			case srcInSet && !dstInSet:
				OtherFromNodeSet.updateAllowedConnsMap(dst, src, conns)
			}
		}
	}
	return OtherToOther, nodeSetToNodeSet, OtherFromNodeSet, OtherToNodeSet
}

// checkConnectivityAbstractionValidity() checks if the abstraction assumption holds
// it does it on each group separately.
// for now it return a string
// todo: - how to report this string? what format?

func checkConnectivityAbstractionValidity(connMap GeneralConnectivityMap, nodeSet NodeSet, isIngress bool) string {
	res := ""
	for node1, nodeConns := range connMap {
		allConns := map[string][]VPCResourceIntf{}
		for node2, conn := range nodeConns {
			// todo - is string unique?
			allConns[conn.String()] = append(allConns[conn.String()], node2)
		}
		if len(allConns) > 1 || len(nodeConns) != len(nodeSet.Nodes()) {
			directionAdjective := map[bool]string{false: "from", true: "to"}[isIngress]
			res += fmt.Sprintf("node %s has different access %s %s:\n", node1.Name(), directionAdjective, nodeSet.Name())
			if len(nodeConns) != len(nodeSet.Nodes()) {
				res += fmt.Sprintf("    it has no access %s ", directionAdjective)
				for _, node2 := range nodeSet.Nodes() {
					if _, ok := nodeConns[node2]; !ok {
						res += fmt.Sprintf("%s, ", node2.Name())
					}
				}
				res += "\n"
			}
			for conn, nodes := range allConns {
				res += "    "
				if isIngress {
					res += fmt.Sprintf("%s -> ", node1.Name())
				}
				for _, n := range nodes {
					res += fmt.Sprintf("%s,", n.Name())
				}
				if !isIngress {
					res += fmt.Sprintf(" -> %s", node1.Name())
				}
				res += fmt.Sprintf(" %s\n", conn)
			}
		}
	}
	// if res != "" {
	// 	fmt.Println("--------------------------------------------------------------")
	// 	fmt.Println(res)
	// }
	return res
}

// mergeConnectivityWithNodeSetAbstraction() merge the four groups, while abstracting the connections
func mergeConnectivityWithNodeSetAbstraction(otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet GeneralConnectivityMap, nodeSet NodeSet) GeneralConnectivityMap {
	// first make a copy of otherToOther, to be the result:
	res := GeneralConnectivityMap{}
	for src, nodeConns := range otherToOther {
		for dst, conns := range nodeConns {
			res.updateAllowedConnsMap(src, dst, conns)
		}
	}
	// all the connections inside the nodeSet are union to one connectivity, added to the result:
	allConns := NoConns()
	for _, nodeConns := range nodeSetToNodeSet {
		for _, conns := range nodeConns {
			allConns = allConns.Union(conns)
		}
	}
	res.updateAllowedConnsMap(nodeSet, nodeSet, allConns)

	// all connection from the nodeSet to a node, are union and added to the result:
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
