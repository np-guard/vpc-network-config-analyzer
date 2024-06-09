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
// it is kept since it is widely used - to determine if the connection is responsive
type detailedConn struct {
	tcpRspEnable  *connection.Set // responsive TCP connection between <src, dst>
	nonTCP        *connection.Set // non TCP connection (for which responsiveness is non-relevant)
	allConn       *connection.Set // entire connection
	tcpRspDisable *connection.Set // non-responsive TCP connection between <src, dst>; complementary of tcpRspEnable
	// connection is defined to be responsive if nonTCP is empty
}

// operation on detailedConn
// The operations are performed on the disjoint tcpRspEnable and nonTCP and on allConn which contains them;
// tcpRspDisable - the tcp complementary of tcpRspEnable w.r.t. allConn -
// is computed as allConn minus (tcpRspEnable union nonTCP)

func newDetailConn(tspRspConn, otherConn, allConn *connection.Set) *detailedConn {
	return &detailedConn{
		tcpRspEnable:  tspRspConn,
		tcpRspDisable: (allConn.Subtract(otherConn)).Subtract(tspRspConn),
		nonTCP:        otherConn,
		allConn:       allConn,
	}
}

func emptyDetailConn() *detailedConn {
	return newDetailConn(NoConns(), NoConns(), NoConns())
}

// detailConnForTCPRspAndNonTCP constructor that is given the (tcp responsive and non tcp) conn and the entire conn
func detailConnForTCPRspAndNonTCP(tcpRspfulAndNonTCP, allConn *connection.Set) *detailedConn {
	tcpRspFraction, nonTCPFraction := partitionTCPNonTCP(tcpRspfulAndNonTCP)
	return newDetailConn(tcpRspFraction, nonTCPFraction, allConn)
}

func detailConnForResponsive(responsive *connection.Set) *detailedConn {
	return newDetailConn(responsive, NoConns(), responsive)
}

func detailConnForAllRsp() *detailedConn {
	return newDetailConn(newTCPSet(), AllConns().Subtract(newTCPSet()), AllConns())
}

func (e *detailedConn) isAllObliviousRsp() bool {
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
	rspConn := e.tcpRspEnable.Union(other.tcpRspEnable)
	otherConn := e.nonTCP.Union(other.nonTCP)
	conn := e.allConn.Union(other.allConn)
	return newDetailConn(rspConn, otherConn, conn)
}

// subtract of two detailedConn: subtraction of tcpRspEnable, nonTCP and allConn
// (tcpRspDisable is computed based on these)
func (e *detailedConn) subtract(other *detailedConn) *detailedConn {
	rspConn := e.tcpRspEnable.Subtract(other.tcpRspEnable)
	otherConn := e.nonTCP.Subtract(other.nonTCP)
	conn := e.allConn.Subtract(other.allConn)
	return newDetailConn(rspConn, otherConn, conn)
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
