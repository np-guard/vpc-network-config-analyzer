/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import "github.com/np-guard/models/pkg/connection"

// todo: remove stateful from connection.Set (for both options)

// ExtendedSet connection details
type ExtendedSet struct {
	statefulConn    *connection.Set // connection between <src, dst>
	nonStatefulConn *connection.Set // reply connection (subseteq connection)
}

func (e *ExtendedSet) String() []string {
	return nil
}

// ConnectivityResultNew is used to capture allowed connectivity between Node elements
// A Node object has its associated ConnectivityResult (see VPCConnectivity.AllowedConns)
// The ConnectivityResult holds the allowed ingress and egress connections (to/from the associated node)
// with other Node objects and the connection attributes for each such node
// todo rename to ConnectivityResult
type ConnectivityResultNew struct {
	IngressAllowedConns map[Node]*ExtendedSet
	EgressAllowedConns  map[Node]*ExtendedSet
}

// GeneralConnectivityMapNew describes connectivity
type GeneralConnectivityMapNew map[VPCResourceIntf]map[VPCResourceIntf]*ExtendedSet

type GeneralConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*connection.Set

func (connectivityMap GeneralConnectivityMap) updateAllowedConnsMap(src, dst VPCResourceIntf, conn *connection.Set) {
	if _, ok := connectivityMap[src]; !ok {
		connectivityMap[src] = map[VPCResourceIntf]*connection.Set{}
	}
	connectivityMap[src][dst] = conn
}
