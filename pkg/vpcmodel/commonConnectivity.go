/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/netp"
)

// todo: remove stateful from connection.Set (for both options)

// ExtendedSet connection details
type ExtendedSet struct {
	statefulConn    *connection.Set // stateful TCP connection between <src, dst>
	nonStatefulConn *connection.Set // nonstateful TCP connection between <src, dst>
	otherConn       *connection.Set // non TCP connection (for which stateful is non-relevant)
	conn            *connection.Set // entire connection
}

// todo: expand and use the stateful vs. non-stateful
func (e *ExtendedSet) String() string {
	return e.conn.String()
}

func (e *ExtendedSet) EnhancedString() string {
	if !e.nonStatefulConn.IsEmpty() {
		return e.String() + " *"
	}
	return e.String()
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

// GeneralStatefulConnectivityMap describes connectivity
type GeneralStatefulConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*ExtendedSet

type GeneralConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*connection.Set

func (connectivityMap GeneralConnectivityMap) updateAllowedConnsMap(src, dst VPCResourceIntf, conn *connection.Set) {
	if _, ok := connectivityMap[src]; !ok {
		connectivityMap[src] = map[VPCResourceIntf]*connection.Set{}
	}
	connectivityMap[src][dst] = conn
}

// it is assumed that the components of extendedConn are legal connection.Set, namely not nil
func (statefulConnMap GeneralStatefulConnectivityMap) updateAllowedStatefulConnsMap(src, dst VPCResourceIntf, extendedConn *ExtendedSet) {
	if _, ok := statefulConnMap[src]; !ok {
		statefulConnMap[src] = map[VPCResourceIntf]*ExtendedSet{}
	}
	statefulConnMap[src][dst] = extendedConn
}

// todo: following functionality needs to be moved to package connection with member instead of parms passing

// todo exists already in connection
func newTCPSet() *connection.Set {
	return connection.TCPorUDPConnection(netp.ProtocolStringTCP, connection.MinPort, connection.MaxPort, connection.MinPort, connection.MaxPort)
}

func partitionTcpNonTcp(conn *connection.Set) (tcp, nonTcp *connection.Set) {
	tcpFractionOfConn := newTCPSet().Intersect(conn)
	nonTcpFractionOfConn := conn.Subtract(tcpFractionOfConn)
	return tcpFractionOfConn, nonTcpFractionOfConn
}
