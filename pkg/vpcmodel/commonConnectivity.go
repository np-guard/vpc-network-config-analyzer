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

// SetWithStateful connection details
type SetWithStateful struct {
	statefulConn    *connection.Set // stateful TCP connection between <src, dst>
	nonStatefulConn *connection.Set // nonstateful TCP connection between <src, dst>; complementary of statefulConn
	otherConn       *connection.Set // non TCP connection (for which stateful is non-relevant)
	conn            *connection.Set // entire connection
}

// operation on SetWithStateful
// The operations are performed on the disjoint statefulConn and otherConn and on conn which contains them;
// nonStatefulConn - the tcp complementary of statefulConn w.r.t. conn -
// is computed as conn minus (statefulConn union otherConn)

func NoConnsSetWithStateful() *SetWithStateful {
	return &SetWithStateful{
		statefulConn:    NoConns(),
		nonStatefulConn: NoConns(),
		otherConn:       NoConns(),
		conn:            NoConns(),
	}
}

func NewStateWithStateful(statefulConn, otherConn, conn *connection.Set) *SetWithStateful {
	return &SetWithStateful{
		statefulConn:    statefulConn,
		nonStatefulConn: conn.Subtract(otherConn).Subtract(statefulConn),
		otherConn:       otherConn,
		conn:            conn,
	}
}

func (e *SetWithStateful) IsAllObliviousStateful() bool {
	return e.conn.Equal(connection.All())
}

func (e *SetWithStateful) IsEmpty() bool {
	return e.conn.IsEmpty()
}

func (e *SetWithStateful) Equal(other *SetWithStateful) bool {
	return e.statefulConn.Equal(other.statefulConn) && e.otherConn.Equal(other.otherConn) &&
		e.conn.Equal(other.conn)
}

func (e *SetWithStateful) Copy() *SetWithStateful {
	return NewStateWithStateful(e.nonStatefulConn.Copy(), e.otherConn.Copy(), e.conn.Copy())
}

func (e *SetWithStateful) Intersect(other *SetWithStateful) *SetWithStateful {
	statefulConn := e.statefulConn.Intersect(other.statefulConn)
	otherConn := e.otherConn.Intersect(other.otherConn)
	conn := e.conn.Intersect(other.conn)
	return NewStateWithStateful(statefulConn, otherConn, conn)
}

func (e *SetWithStateful) Union(other *SetWithStateful) *SetWithStateful {
	statefulConn := e.statefulConn.Union(other.statefulConn)
	otherConn := e.otherConn.Union(other.otherConn)
	conn := e.conn.Union(other.conn)
	return NewStateWithStateful(statefulConn, otherConn, conn)
}

func (e *SetWithStateful) Subtract(other *SetWithStateful) *SetWithStateful {
	statefulConn := e.statefulConn.Subtract(other.statefulConn)
	otherConn := e.otherConn.Subtract(other.otherConn)
	conn := e.conn.Subtract(other.conn)
	return NewStateWithStateful(statefulConn, otherConn, conn)
}

func (e *SetWithStateful) String() string {
	return e.conn.String()
}

func (e *SetWithStateful) EnhancedString() string {
	if !e.nonStatefulConn.IsEmpty() {
		return e.String() + " *"
	}
	return e.String()
}

// ///////////////////////////////////////////////////////////////////////////////////////////

// GeneralStatefulConnectivityMap describes connectivity
type GeneralStatefulConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*SetWithStateful

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
	dst VPCResourceIntf, extendedConn *SetWithStateful) {
	if _, ok := statefulConnMap[src]; !ok {
		statefulConnMap[src] = map[VPCResourceIntf]*SetWithStateful{}
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
