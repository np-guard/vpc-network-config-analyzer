/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"reflect"
	"sort"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
)

type ConnectivityResultMap map[*ipblock.IPBlock]*ConnectivityResult

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
	keys1 := make([]string, 0, len(conns1))
	for i := range conns1 {
		keys1 = append(keys1, i.String())
	}
	sort.Strings(keys1)
	keys2 := make([]string, 0, len(conns2))
	for i := range conns2 {
		keys2 = append(keys2, i.String())
	}
	sort.Strings(keys2)
	// compare the concatenation result to validate equality of keys sets
	for i := 0; i < len(keys1); i++ {
		if keys1[i] != keys2[i] {
			return false
		}
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
	keys1 := make([]string, 0, len(rules1))
	for i := range rules1 {
		keys1 = append(keys1, i.String())
	}
	sort.Strings(keys1)
	keys2 := make([]string, 0, len(rules2))
	for i := range rules2 {
		keys2 = append(keys2, i.String())
	}
	sort.Strings(keys2)
	// compare the concatenation result to validate equality of keys sets
	for i := 0; i < len(keys1); i++ {
		if keys1[i] != keys2[i] {
			return false
		}
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

func (cr *ConnectivityResultMap) Equal(other *ConnectivityResultMap) bool {
	if len(*cr) != len(*other) {
		return false
	}
	for ip, connectivityResult := range *cr {
		for expectedIP, expectedConnectivityResult := range *other {
			if ip.Equal(expectedIP) {
				if !connectivityResult.Equal(expectedConnectivityResult) {
					return false
				}
				break
			}
		}
	}
	return true
}
