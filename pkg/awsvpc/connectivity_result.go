/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"reflect"
	"sort"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
)

// ConnectivityResultMap is a map from IPBlock to ConnectivityResult, used to map disjointLocals IPBlocks to ConnectivityResult
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

func storeAndSortKeys[T any](m map[*ipblock.IPBlock]T) []string {
	keys := make([]string, len(m))
	i := 0
	for ipBlock := range m {
		keys[i] = ipBlock.String()
		i += 1
	}
	sort.Strings(keys)
	return keys
}

func equalKeys[T any](first, second map[*ipblock.IPBlock]T) bool {
	if len(first) != len(second) {
		return false
	}
	keys1 := storeAndSortKeys(first)
	keys2 := storeAndSortKeys(second)
	// compare the concatenation result to validate equality of keys sets
	return reflect.DeepEqual(keys1, keys2)
}

func equalConns(conns1, conns2 map[*ipblock.IPBlock]*connection.Set) bool {
	if !equalKeys(conns1, conns2) {
		return false
	}
	for ipBlock, conn := range conns1 {
		for otherIPBlock, otherConn := range conns2 {
			if ipBlock.Equal(otherIPBlock) {
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
	if !equalKeys(rules1, rules2) {
		return false
	}
	for ipBlock, indexes := range rules1 {
		for otherIPBlock, otherIndexes := range rules2 {
			if ipBlock.Equal(otherIPBlock) {
				sort.Ints(indexes)
				sort.Ints(otherIndexes)
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

func (cr ConnectivityResultMap) Equal(other ConnectivityResultMap) bool {
	if !equalKeys(cr, other) {
		return false
	}
	for ipBlock, connectivityResult := range cr {
		for otherIPBlock, expectedConnectivityResult := range other {
			if ipBlock.Equal(otherIPBlock) {
				if !connectivityResult.Equal(expectedConnectivityResult) {
					return false
				}
				break
			}
		}
	}
	return true
}
