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

// detailedConn captures full connection details, as described below.
// It is created from src to dest allowed connection (TCP and non-TCP) and response dest to src allowed connection
// (TCP and non-TCP); further entities of the connection may be created from operations as Union e.g. for abstraction
type detailedConn struct {
	statefulConn    *connection.Set // stateful TCP connection between <src, dst>
	nonStatefulConn *connection.Set // nonstateful TCP connection between <src, dst>; complementary of statefulConn
	// connection is defined to be stateful if otherConn is empty
	otherConn *connection.Set // non TCP connection (for which stateful is non-relevant)
	allConn   *connection.Set // entire connection
}

// operation on detailedConn
// The operations are performed on the disjoint statefulConn and otherConn and on allConn which contains them;
// nonStatefulConn - the tcp complementary of statefulConn w.r.t. allConn -
// is computed as allConn minus (statefulConn union otherConn)

func newDetailConn(statefulConn, otherConn, allConn *connection.Set) *detailedConn {
	return &detailedConn{
		statefulConn:    statefulConn,
		nonStatefulConn: allConn.Subtract(otherConn).Subtract(statefulConn),
		otherConn:       otherConn,
		allConn:         allConn,
	}
}

func emptyConnWithStateful() *detailedConn {
	return &detailedConn{
		statefulConn:    NoConns(),
		nonStatefulConn: NoConns(),
		otherConn:       NoConns(),
		allConn:         NoConns(),
	}
}

// detailConnForTCPStatefulAndNonTCP constructor that is given the (tcp stateful and non tcp) conn and the entire conn
func detailConnForTCPStatefulAndNonTCP(tcpStatefulAndNonTCP, allConn *connection.Set) *detailedConn {
	tcpStatefulFraction, nonTCPFraction := partitionTCPNonTCP(tcpStatefulAndNonTCP)
	return newDetailConn(tcpStatefulFraction, nonTCPFraction, allConn)
}

func detailConnForStateful(stateful *connection.Set) *detailedConn {
	return &detailedConn{
		statefulConn:    stateful,
		nonStatefulConn: NoConns(),
		otherConn:       NoConns(),
		allConn:         stateful,
	}
}

func detailConnForAllStateful() *detailedConn {
	return &detailedConn{
		statefulConn:    newTCPSet(),
		nonStatefulConn: NoConns(),
		otherConn:       NoConns(),
		allConn:         AllConns(),
	}
}

func (e *detailedConn) copy() *detailedConn {
	return newDetailConn(e.nonStatefulConn.Copy(), e.otherConn.Copy(), e.allConn.Copy())
}

func (e *detailedConn) isAllObliviousStateful() bool {
	return e.allConn.Equal(connection.All())
}

func (e *detailedConn) isEmpty() bool {
	return e.allConn.IsEmpty()
}

// Equal all components of two detailedConn are equal
func (e *detailedConn) Equal(other *detailedConn) bool {
	return e.statefulConn.Equal(other.statefulConn) && e.otherConn.Equal(other.otherConn) &&
		e.allConn.Equal(other.allConn)
}

// Intersect of two detailedConn: intersecting statefulConn, otherConn and allConn
// (nonStatefulConn is computed based on these)
func (e *detailedConn) Intersect(other *detailedConn) *detailedConn {
	statefulConn := e.statefulConn.Intersect(other.statefulConn)
	otherConn := e.otherConn.Intersect(other.otherConn)
	conn := e.allConn.Intersect(other.allConn)
	return newDetailConn(statefulConn, otherConn, conn)
}

// Union of two detailedConn: union statefulConn, otherConn and allConn
// (nonStatefulConn is computed based on these)
func (e *detailedConn) Union(other *detailedConn) *detailedConn {
	statefulConn := e.statefulConn.Union(other.statefulConn)
	otherConn := e.otherConn.Union(other.otherConn)
	conn := e.allConn.Union(other.allConn)
	return newDetailConn(statefulConn, otherConn, conn)
}

// Subtract of two detailedConn: subtraction of statefulConn, otherConn and allConn
// (nonStatefulConn is computed based on these)
func (e *detailedConn) Subtract(other *detailedConn) *detailedConn {
	statefulConn := e.statefulConn.Subtract(other.statefulConn)
	otherConn := e.otherConn.Subtract(other.otherConn)
	conn := e.allConn.Subtract(other.allConn)
	return newDetailConn(statefulConn, otherConn, conn)
}

func (e *detailedConn) string() string {
	return e.allConn.String()
}

func (e *detailedConn) enhancedString() string {
	if !e.nonStatefulConn.IsEmpty() {
		return e.string() + " * "
	}
	return e.string()
}

// ///////////////////////////////////////////////////////////////////////////////////////////

// GeneralStatefulConnectivityMap describes connectivity
type GeneralStatefulConnectivityMap map[VPCResourceIntf]map[VPCResourceIntf]*detailedConn

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

// it is assumed that the components of detailedConn are legal connection.Set, namely not nil
func (statefulConnMap GeneralStatefulConnectivityMap) updateAllowedStatefulConnsMap(src,
	dst VPCResourceIntf, conn *detailedConn) {
	if _, ok := statefulConnMap[src]; !ok {
		statefulConnMap[src] = map[VPCResourceIntf]*detailedConn{}
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
