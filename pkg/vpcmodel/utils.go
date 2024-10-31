/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"github.com/np-guard/models/pkg/netset"
)

func AllConns() *netset.TransportSet {
	return netset.AllTransports()
}

func NoConns() *netset.TransportSet {
	return netset.NoTransports()
}

func HasNode(listNodes []Node, node Node) bool {
	for _, n := range listNodes {
		if n.UID() == node.UID() {
			return true
		}
	}
	return false
}
