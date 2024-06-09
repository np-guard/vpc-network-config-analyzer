/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/netp"
)

// todo: remove stateful from connection.Set

// detailedConn captures the connection with connection's responsive details, as described below.
// It is created from src to dest allowed connection (TCP and non-TCP) and response dest to src allowed connection
// (TCP and non-TCP); further entities of the connection may be created from operations as union e.g. for abstraction
// note: tcpRspDisable is not independent and is calculated based on the other properties;
// it is kept since it is widely used - to determine if the connection is stateful
type detailedConn struct {
	tcpRspEnable  *connection.Set // responsive TCP connection between <src, dst>
	nonTCP        *connection.Set // non TCP connection (for which stateful is non-relevant)
	allConn       *connection.Set // entire connection
	tcpRspDisable *connection.Set // non-responsive TCP connection between <src, dst>; complementary of tcpRspEnable
	// connection is defined to be stateful if nonTCP is empty
}

// operation on detailedConn
// The operations are performed on the disjoint tcpRspEnable and nonTCP and on allConn which contains them;
// tcpRspDisable - the tcp complementary of tcpRspEnable w.r.t. allConn -
// is computed as allConn minus (tcpRspEnable union nonTCP)

func newDetailConn(statefulConn, otherConn, allConn *connection.Set) *detailedConn {
	return &detailedConn{
		tcpRspEnable:  statefulConn,
		tcpRspDisable: (allConn.Subtract(otherConn)).Subtract(statefulConn),
		nonTCP:        otherConn,
		allConn:       allConn,
	}
}

func emptyDetailConn() *detailedConn {
	return newDetailConn(NoConns(), NoConns(), NoConns())
}

// detailConnForTCPStatefulAndNonTCP constructor that is given the (tcp stateful and non tcp) conn and the entire conn
func detailConnForTCPStatefulAndNonTCP(tcpStatefulAndNonTCP, allConn *connection.Set) *detailedConn {
	tcpStatefulFraction, nonTCPFraction := partitionTCPNonTCP(tcpStatefulAndNonTCP)
	return newDetailConn(tcpStatefulFraction, nonTCPFraction, allConn)
}

func detailConnForStateful(stateful *connection.Set) *detailedConn {
	return newDetailConn(stateful, NoConns(), stateful)
}

func detailConnForAllStateful() *detailedConn {
	return newDetailConn(newTCPSet(), AllConns().Subtract(newTCPSet()), AllConns())
}

func (e *detailedConn) isAllObliviousStateful() bool {
	return e.allConn.Equal(connection.All())
}

func (e *detailedConn) isEmpty() bool {
	return e.allConn.IsEmpty()
}

// Equal all components of two detailedConn are equal
func (e *detailedConn) equal(other *detailedConn) bool {
	return e.tcpRspEnable.Equal(other.tcpRspEnable) && e.nonTCP.Equal(other.nonTCP) &&
		e.allConn.Equal(other.allConn)
}

// union of two detailedConn: union tcpRspEnable, nonTCP and allConn
// (tcpRspDisable is computed based on these)
func (e *detailedConn) union(other *detailedConn) *detailedConn {
	statefulConn := e.tcpRspEnable.Union(other.tcpRspEnable)
	otherConn := e.nonTCP.Union(other.nonTCP)
	conn := e.allConn.Union(other.allConn)
	return newDetailConn(statefulConn, otherConn, conn)
}

// subtract of two detailedConn: subtraction of tcpRspEnable, nonTCP and allConn
// (tcpRspDisable is computed based on these)
func (e *detailedConn) subtract(other *detailedConn) *detailedConn {
	statefulConn := e.tcpRspEnable.Subtract(other.tcpRspEnable)
	otherConn := e.nonTCP.Subtract(other.nonTCP)
	conn := e.allConn.Subtract(other.allConn)
	return newDetailConn(statefulConn, otherConn, conn)
}

func (e *detailedConn) string() string {
	if !e.tcpRspDisable.IsEmpty() {
		return e.allConn.String() + " * "
	}
	return e.allConn.String()
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
