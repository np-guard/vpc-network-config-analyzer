/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"fmt"
	"slices"
)

func nodeSetConnectivityAbstraction(nodesConn GeneralConnectivityMap, nodeSet NodeSet) GeneralConnectivityMap {
	otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet := splitConnectivityByNodeSet(nodesConn, nodeSet)
	diagnoseConnectivityAbstraction(otherFromNodeSet, false)
	diagnoseConnectivityAbstraction(otherToNodeSet, true)
	diagnoseConnectivityAbstraction(nodeSetToNodeSet, true)
	return mergeConnectivityWithNodeSetAbstraction(otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet, nodeSet)
}

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
func diagnoseConnectivityAbstraction(connMap GeneralConnectivityMap, isIngress bool) {
	for node1, nodeConns := range connMap {
		allConns := map[string][]VPCResourceIntf{}
		for node2, conns := range nodeConns {
			// todo - is string unique?
			allConns[conns.String()] = append(allConns[conns.String()], node2)
		}
		if len(allConns) > 1 {
			fmt.Printf(" node %s has different access %s the nodeSet:\n", node1.Name(), map[bool]string{false: "from", true: "to"}[isIngress])
			for conn, nodes := range allConns {
				if !isIngress {
					fmt.Printf("%s -> ", node1.Name())
				}
				for _, n := range nodes {
					fmt.Printf("%s,", n.Name())
				}
				if isIngress {
					fmt.Printf(" -> %s", node1.Name())
				}
				fmt.Printf(" %s\n", conn)
			}
		}
	}
}

func mergeConnectivityWithNodeSetAbstraction(otherToOther, nodeSetToNodeSet, otherFromNodeSet, otherToNodeSet GeneralConnectivityMap, nodeSet NodeSet) GeneralConnectivityMap {
	res := GeneralConnectivityMap{}
	for src, nodeConns := range otherToOther {
		for dst, conns := range nodeConns {
			res.updateAllowedConnsMap(src, dst, conns)
		}
	}

	allConns := NoConns()
	for _, nodeConns := range nodeSetToNodeSet {
		for _, conns := range nodeConns {
			allConns = conns.Union(conns)
		}
	}
	res.updateAllowedConnsMap(nodeSet, nodeSet, allConns)

	for src, nodeConns := range otherToNodeSet {
		allConns := NoConns()
		for _, conns := range nodeConns {
			allConns = conns.Union(conns)
		}
		res.updateAllowedConnsMap(src, nodeSet, allConns)
	}
	for dst, nodeConns := range otherFromNodeSet {
		allConns := NoConns()
		for _, conns := range nodeConns {
			allConns = conns.Union(conns)
		}
		res.updateAllowedConnsMap(nodeSet, dst, allConns)
	}
	return res
}
