/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
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
