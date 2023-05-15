package vpcmodel

import "github.com/np-guard/vpc-network-config-analyzer/pkg/common"

func AllConns() *common.ConnectionSet {
	res := common.MakeConnectionSet(true)
	return &res
}

func NoConns() *common.ConnectionSet {
	res := common.MakeConnectionSet(false)
	return &res
}

func HasNode(listNodes []Node, node Node) bool {
	for _, n := range listNodes {
		if n.Cidr() == node.Cidr() {
			return true
		}
	}
	return false
}
