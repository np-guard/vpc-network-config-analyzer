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

// connWithStateful connection details
type connWithStateful struct {
	statefulConn    *connection.Set // stateful TCP connection between <src, dst>
	nonStatefulConn *connection.Set // nonstateful TCP connection between <src, dst>; complementary of statefulConn
	otherConn       *connection.Set // non TCP connection (for which stateful is non-relevant)
	allConn         *connection.Set // entire connection
}

// operation on connWithStateful
// The operations are performed on the disjoint statefulConn and otherConn and on allConn which contains them;
// nonStatefulConn - the tcp complementary of statefulConn w.r.t. allConn -
// is computed as allConn minus (statefulConn union otherConn)

func computeNonStatefulConn(allConn, otherConn, statefulConn *connection.Set) *connection.Set {
	return allConn.Subtract(otherConn).Subtract(statefulConn)
}

func EmptyConnWithStateful() *connWithStateful {
	return &connWithStateful{
		statefulConn:    NoConns(),
		nonStatefulConn: NoConns(),
		otherConn:       NoConns(),
		allConn:         NoConns(),
	}
}

func NewConnWithStateful(statefulConn, otherConn, allConn *connection.Set) *connWithStateful {
	return &connWithStateful{
		statefulConn:    statefulConn,
		nonStatefulConn: computeNonStatefulConn(allConn, otherConn, statefulConn),
		otherConn:       otherConn,
		allConn:         allConn,
	}
}

// NewConnWithStatefulGivenTCPStatefulAndNonTCP constructor that is given the (tcp stateful and non tcp) conn and the entire conn
func NewConnWithStatefulGivenTCPStatefulAndNonTCP(tcpStatefulAndNonTCP, allConn *connection.Set) *connWithStateful {
	tcpStatefulFraction, nonTCPFraction := partitionTCPNonTCP(tcpStatefulAndNonTCP)
	return &connWithStateful{
		statefulConn:    tcpStatefulFraction,
		nonStatefulConn: computeNonStatefulConn(allConn, nonTCPFraction, tcpStatefulFraction),
		otherConn:       nonTCPFraction,
		allConn:         allConn,
	}
}

func NewConnWithStatefulGivenStateful(stateful *connection.Set) *connWithStateful {
	return &connWithStateful{
		statefulConn:    stateful,
		nonStatefulConn: NoConns(),
		otherConn:       NoConns(),
		allConn:         stateful,
	}
}

func NewConnWithStatefulAllStateful() *connWithStateful {
	return &connWithStateful{
		statefulConn:    newTCPSet(),
		nonStatefulConn: NoConns(),
		otherConn:       NoConns(),
		allConn:         AllConns(),
	}
}

func NewConnWithStatefulAllNotStateful() *connWithStateful {
	return &connWithStateful{
		statefulConn:    NoConns(),
		nonStatefulConn: newTCPSet(),
		otherConn:       AllConns().Subtract(newTCPSet()),
		allConn:         AllConns(),
	}
}

func (e *connWithStateful) IsAllObliviousStateful() bool {
	return e.allConn.Equal(connection.All())
}

func (e *connWithStateful) IsEmpty() bool {
	return e.allConn.IsEmpty()
}

func (e *connWithStateful) Equal(other *connWithStateful) bool {
	return e.statefulConn.Equal(other.statefulConn) && e.otherConn.Equal(other.otherConn) &&
		e.allConn.Equal(other.allConn)
}

func (e *connWithStateful) Copy() *connWithStateful {
	return NewConnWithStateful(e.nonStatefulConn.Copy(), e.otherConn.Copy(), e.allConn.Copy())
}

func (e *connWithStateful) Intersect(other *connWithStateful) *connWithStateful {
	statefulConn := e.statefulConn.Intersect(other.statefulConn)
	otherConn := e.otherConn.Intersect(other.otherConn)
	conn := e.allConn.Intersect(other.allConn)
	return NewConnWithStateful(statefulConn, otherConn, conn)
}

func (e *connWithStateful) Union(other *connWithStateful) *connWithStateful {
	statefulConn := e.statefulConn.Union(other.statefulConn)
	otherConn := e.otherConn.Union(other.otherConn)
	conn := e.allConn.Union(other.allConn)
	return NewConnWithStateful(statefulConn, otherConn, conn)
}

func (e *connWithStateful) Subtract(other *connWithStateful) *connWithStateful {
	statefulConn := e.statefulConn.Subtract(other.statefulConn)
	otherConn := e.otherConn.Subtract(other.otherConn)
	conn := e.allConn.Subtract(other.allConn)
	return NewConnWithStateful(statefulConn, otherConn, conn)
}

func (e *connWithStateful) String() string {
	return e.allConn.String()
}

func (e *connWithStateful) EnhancedString() string {
	if !e.nonStatefulConn.IsEmpty() {
		return e.String() + " * "
	}
	return e.String()
}

// ///////////////////////////////////////////////////////////////////////////////////////////

// GeneralStatefulConnectivityMap describes connectivity
type GeneralStatefulConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*connWithStateful

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

// it is assumed that the components of connWithStateful are legal connection.Set, namely not nil
func (statefulConnMap GeneralStatefulConnectivityMap) updateAllowedStatefulConnsMap(src,
	dst VPCResourceIntf, conn *connWithStateful) {
	if _, ok := statefulConnMap[src]; !ok {
		statefulConnMap[src] = map[VPCResourceIntf]*connWithStateful{}
	}
	statefulConnMap[src][dst] = conn
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
