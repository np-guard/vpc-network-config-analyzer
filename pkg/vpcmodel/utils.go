package vpcmodel

import (
	"github.com/np-guard/models/pkg/connection"
)

func AllConns() *connection.Set {
	return connection.All()
}

func NoConns() *connection.Set {
	return connection.None()
}

func HasNode(listNodes []Node, node Node) bool {
	for _, n := range listNodes {
		if n.UID() == node.UID() {
			return true
		}
	}
	return false
}
