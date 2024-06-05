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

// ConnWithStateful connection details
type ConnWithStateful struct {
	statefulConn    *connection.Set // stateful TCP connection between <src, dst>
	nonStatefulConn *connection.Set // nonstateful TCP connection between <src, dst>; complementary of statefulConn
	otherConn       *connection.Set // non TCP connection (for which stateful is non-relevant)
	allConn         *connection.Set // entire connection
}

// operation on ConnWithStateful
// The operations are performed on the disjoint statefulConn and otherConn and on allConn which contains them;
// nonStatefulConn - the tcp complementary of statefulConn w.r.t. allConn -
// is computed as allConn minus (statefulConn union otherConn)

func computeNonStatefulConn(allConn, otherConn, statefulConn *connection.Set) *connection.Set {
	return allConn.Subtract(otherConn).Subtract(statefulConn)
}

func EmptyConnWithStateful() *ConnWithStateful {
	return &ConnWithStateful{
		statefulConn:    NoConns(),
		nonStatefulConn: NoConns(),
		otherConn:       NoConns(),
		allConn:         NoConns(),
	}
}

func NewConnWithStateful(statefulConn, otherConn, allConn *connection.Set) *ConnWithStateful {
	return &ConnWithStateful{
		statefulConn:    statefulConn,
		nonStatefulConn: computeNonStatefulConn(allConn, otherConn, statefulConn),
		otherConn:       otherConn,
		allConn:         allConn,
	}
}

// NewConnWithStatefulGivenStateful constructor that is given the (tcp stateful and non tcp) conn and the entire conn
func NewConnWithStatefulGivenStateful(tcpStatefulandNonTcp, allConn *connection.Set) *ConnWithStateful {
	tcpStatefulFraction, nonTCPFraction := partitionTCPNonTCP(tcpStatefulandNonTcp)
	return &ConnWithStateful{
		statefulConn:    tcpStatefulFraction,
		nonStatefulConn: computeNonStatefulConn(allConn, nonTCPFraction, tcpStatefulFraction),
		otherConn:       nonTCPFraction,
		allConn:         allConn,
	}
}

func (e *ConnWithStateful) IsAllObliviousStateful() bool {
	return e.allConn.Equal(connection.All())
}

func (e *ConnWithStateful) IsEmpty() bool {
	return e.allConn.IsEmpty()
}

func (e *ConnWithStateful) Equal(other *ConnWithStateful) bool {
	return e.statefulConn.Equal(other.statefulConn) && e.otherConn.Equal(other.otherConn) &&
		e.allConn.Equal(other.allConn)
}

func (e *ConnWithStateful) Copy() *ConnWithStateful {
	return NewConnWithStateful(e.nonStatefulConn.Copy(), e.otherConn.Copy(), e.allConn.Copy())
}

func (e *ConnWithStateful) Intersect(other *ConnWithStateful) *ConnWithStateful {
	statefulConn := e.statefulConn.Intersect(other.statefulConn)
	otherConn := e.otherConn.Intersect(other.otherConn)
	conn := e.allConn.Intersect(other.allConn)
	return NewConnWithStateful(statefulConn, otherConn, conn)
}

func (e *ConnWithStateful) Union(other *ConnWithStateful) *ConnWithStateful {
	statefulConn := e.statefulConn.Union(other.statefulConn)
	otherConn := e.otherConn.Union(other.otherConn)
	conn := e.allConn.Union(other.allConn)
	return NewConnWithStateful(statefulConn, otherConn, conn)
}

func (e *ConnWithStateful) Subtract(other *ConnWithStateful) *ConnWithStateful {
	statefulConn := e.statefulConn.Subtract(other.statefulConn)
	otherConn := e.otherConn.Subtract(other.otherConn)
	conn := e.allConn.Subtract(other.allConn)
	return NewConnWithStateful(statefulConn, otherConn, conn)
}

func (e *ConnWithStateful) String() string {
	return e.allConn.String()
}

func (e *ConnWithStateful) EnhancedString() string {
	if !e.nonStatefulConn.IsEmpty() {
		return e.String() + " *"
	}
	return e.String()
}

// ///////////////////////////////////////////////////////////////////////////////////////////

// GeneralStatefulConnectivityMap describes connectivity
type GeneralStatefulConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*ConnWithStateful

type GeneralConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*connection.Set

func (connectivityMap GeneralConnectivityMap) updateAllowedConnsMap(src, dst VPCResourceIntf, conn *connection.Set) {
	if _, ok := connectivityMap[src]; !ok {
		connectivityMap[src] = map[VPCResourceIntf]*connection.Set{}
	}
	connectivityMap[src][dst] = conn
}

func (statefulConnMap GeneralStatefulConnectivityMap) updateMap(connectivityMap2 GeneralStatefulConnectivityMap) {
	for src, nodeConns := range connectivityMap2 {
		for dst, conns := range nodeConns {
			statefulConnMap.updateAllowedStatefulConnsMap(src, dst, conns)
		}
	}
}
func (statefulConnMap GeneralStatefulConnectivityMap) copy() GeneralStatefulConnectivityMap {
	newConnectivityMap := GeneralStatefulConnectivityMap{}
	newConnectivityMap.updateMap(statefulConnMap)
	return newConnectivityMap
}

// it is assumed that the components of extendedConn are legal connection.Set, namely not nil
func (statefulConnMap GeneralStatefulConnectivityMap) updateAllowedStatefulConnsMap(src,
	dst VPCResourceIntf, extendedConn *ConnWithStateful) {
	if _, ok := statefulConnMap[src]; !ok {
		statefulConnMap[src] = map[VPCResourceIntf]*ConnWithStateful{}
	}
	statefulConnMap[src][dst] = extendedConn
}

/////////////////////////////////////////////////////////////////////////////////////////////////

// todo: following functionality needs to be moved to package connection with member instead of parms passing

func newTCPSet() *connection.Set {
	return connection.TCPorUDPConnection(netp.ProtocolStringTCP, connection.MinPort, connection.MaxPort,
		connection.MinPort, connection.MaxPort)
}

func partitionTCPNonTCP(conn *connection.Set) (tcp, nonTCP *connection.Set) {
	tcpFractionOfConn := newTCPSet().Intersect(conn)
	nonTCPFractionOfConn := conn.Subtract(tcpFractionOfConn)
	return tcpFractionOfConn, nonTCPFractionOfConn
}
