package vpcmodel

import "github.com/np-guard/vpc-network-config-analyzer/pkg/common"

func AllConns() *common.ConnectionSet {
	return common.NewConnectionSet(true)
}

func NoConns() *common.ConnectionSet {
	return common.NewConnectionSet(false)
}

func HasNode(listNodes []Node, node Node) bool {
	for _, n := range listNodes {
		if n.Cidr() == node.Cidr() {
			return true
		}
	}
	return false
}
