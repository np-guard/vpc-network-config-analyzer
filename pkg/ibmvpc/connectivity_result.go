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

func (cr *ConnectivityResult) Equal(other *ConnectivityResult) bool {
	if cr.isIngress != other.isIngress || len(cr.allowedConns) != len(other.allowedConns) || len(cr.allowRules) != len(other.allowRules) ||
		len(cr.deniedConns) != len(other.deniedConns) || len(cr.denyRules) != len(other.denyRules) {
		return false
	}
	for ip, conn := range cr.allowedConns {
		for otherIp, otherConn := range other.allowedConns {
			if ip.Equal(otherIp) {
				if !conn.Equal(otherConn) {
					return false
				}
				break
			}
		}
	}
	for ip, indexes := range cr.allowRules {
		for otherIp, otherIndexes := range other.allowRules {
			if ip.Equal(otherIp) {
				if !reflect.DeepEqual(indexes, otherIndexes) {
					return false
				}
				break
			}
		}
	}
	for ip, conn := range cr.deniedConns {
		for otherIp, otherConn := range other.deniedConns {
			if ip.Equal(otherIp) {
				if !conn.Equal(otherConn) {
					return false
				}
				break
			}
		}
	}
	for ip, indexes := range cr.denyRules {
		for otherIp, otherIndexes := range other.denyRules {
			if ip.Equal(otherIp) {
				if !reflect.DeepEqual(indexes, otherIndexes) {
					return false
				}
				break
			}
		}
	}
	return true
}
