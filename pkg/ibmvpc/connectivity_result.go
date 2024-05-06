/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"reflect"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
)

// ConnectivityResult is built on disjoint ip-blocks for targets of all relevant sg/nacl results
// ConnectivityResult is per VSI network interface: contains allowed connectivity (with connection attributes) per target
type ConnectivityResult struct {
	isIngress    bool
	allowedConns map[*ipblock.IPBlock]*connection.Set // allowed target and its allowed connections
	allowRules   map[*ipblock.IPBlock][]int           // indexes of (positive) allowRules contributing to this connectivity
	// the following are relevant only to filters with deny rules - nacl
	deniedConns map[*ipblock.IPBlock]*connection.Set // denied target and its allowed connections, by deny rules.
	denyRules   map[*ipblock.IPBlock][]int           // indexes of deny rules relevant to this connectivity
}

func equalConns(conns1, conns2 map[*ipblock.IPBlock]*connection.Set) bool {
	if len(conns1) != len(conns2) {
		return false
	}
	for ip, conn := range conns1 {
		for otherIP, otherConn := range conns2 {
			if ip.Equal(otherIP) {
				if !conn.Equal(otherConn) {
					return false
				}
				break
			}
		}
	}
	return true
}

func equalRules(rules1, rules2 map[*ipblock.IPBlock][]int) bool {
	if len(rules1) != len(rules2) {
		return false
	}
	for ip, indexes := range rules1 {
		for otherIP, otherIndexes := range rules2 {
			if ip.Equal(otherIP) {
				if !reflect.DeepEqual(indexes, otherIndexes) {
					return false
				}
				break
			}
		}
	}
	return true
}

func (cr *ConnectivityResult) Equal(other *ConnectivityResult) bool {
	if cr.isIngress != other.isIngress {
		return false
	}
	return equalConns(cr.allowedConns, other.allowedConns) &&
		equalConns(cr.deniedConns, other.deniedConns) &&
		equalRules(cr.allowRules, other.allowRules) &&
		equalRules(cr.denyRules, other.denyRules)
}
