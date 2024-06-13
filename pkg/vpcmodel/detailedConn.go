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

func (d *detailedConn) isAllObliviousRsp() bool {
	return d.allConn.Equal(connection.All())
}

func (d *detailedConn) isEmpty() bool {
	return d.allConn.IsEmpty()
}

// Equal all components of two detailedConn are equal
func (d *detailedConn) equal(other *detailedConn) bool {
	return d.tcpRspEnable.Equal(other.tcpRspEnable) && d.nonTCP.Equal(other.nonTCP) &&
		d.allConn.Equal(other.allConn)
}

// union of two detailedConn: union tcpRspEnable, nonTCP and allConn
// (tcpRspDisable is computed based on these)
func (d *detailedConn) union(other *detailedConn) *detailedConn {
	rspConn := d.tcpRspEnable.Union(other.tcpRspEnable)
	otherConn := d.nonTCP.Union(other.nonTCP)
	conn := d.allConn.Union(other.allConn)
	return newDetailConn(rspConn, otherConn, conn)
}

// subtract of two detailedConn: subtraction of tcpRspEnable, nonTCP and allConn
// (tcpRspDisable is computed based on these)
func (d *detailedConn) subtract(other *detailedConn) *detailedConn {
	rspConn := d.tcpRspEnable.Subtract(other.tcpRspEnable)
	otherConn := d.nonTCP.Subtract(other.nonTCP)
	conn := d.allConn.Subtract(other.allConn)
	return newDetailConn(rspConn, otherConn, conn)
}

func (d *detailedConn) string() string {
	if !d.tcpRspDisable.IsEmpty() {
		return d.allConn.String() + " * "
	}
	return d.allConn.String()
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
