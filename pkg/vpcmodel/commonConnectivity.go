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

// GeneralStatefulConnectivityMap describes connectivity
type GeneralStatefulConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*ExtendedSet

type GeneralConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*connection.Set

func (connectivityMap GeneralConnectivityMap) updateAllowedConnsMap(src, dst VPCResourceIntf, conn *connection.Set) {
	if _, ok := connectivityMap[src]; !ok {
		connectivityMap[src] = map[VPCResourceIntf]*connection.Set{}
	}
	connectivityMap[src][dst] = conn
}

func (connectivityMap GeneralStatefulConnectivityMap) updateAllowedConnsMapNew(src, dst VPCResourceIntf, conn *ExtendedSet) {
	if _, ok := connectivityMap[src]; !ok {
		connectivityMap[src] = map[VPCResourceIntf]*ExtendedSet{}
	}
	connectivityMap[src][dst] = conn
}

// todo: following functionality needs to be moved to package connection member of (c *Set)

// todo exists already in connection
func newTCPSet() *connection.Set {
	return connection.TCPorUDPConnection(netp.ProtocolStringTCP, connection.MinPort, connection.MaxPort, connection.MinPort, connection.MaxPort)
}

func partitionTcpNonTcp(conn *connection.Set) (tcp, nonTcp *connection.Set) {
	tcpFractionOfConn := newTCPSet().Intersect(conn)
	nonTcpFractionOfConn := conn.Subtract(tcpFractionOfConn)
	return tcpFractionOfConn, nonTcpFractionOfConn
}
