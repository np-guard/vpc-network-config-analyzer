/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"github.com/np-guard/models/pkg/connection"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// detailedConn captures the connection with TCP's responsiveness details, as described below.
// It is created from src-to-dest allowed connection (TCP and non-TCP) and allowed response
// connection dest-to-src.

// Note that allowed response connection differs from the allowed dest-to-src connection.
// Specifically, this is relevant when in response to a TCP src to dst connection, dest initiates a dst to src response.

// Further entities of the connection may be created from operations as union e.g. for abstraction
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

func newDetailedConn(tspRspConn, otherConn, allConn *connection.Set) *detailedConn {
	return &detailedConn{
		tcpRspEnable:  tspRspConn,
		tcpRspDisable: (allConn.Subtract(otherConn)).Subtract(tspRspConn),
		nonTCP:        otherConn,
		allConn:       allConn,
	}
}

func emptyDetailedConn() *detailedConn {
	return newDetailedConn(NoConns(), NoConns(), NoConns())
}

// detailedConnForTCPRsp returns a new detailedConn from input TCP responsive connection and the entire connection objects
func detailedConnForTCPRsp(tcpResponsive, allConn *connection.Set) *detailedConn {
	_, nonTCPFraction := partitionTCPNonTCP(allConn)
	return newDetailedConn(tcpResponsive, nonTCPFraction, allConn)
}

// detailedConnForResponsive: is given the tcp responsive conn, assuming there is only
// a tcp responsive component in the connection
func detailedConnForResponsive(tcpResponsive *connection.Set) *detailedConn {
	return newDetailedConn(tcpResponsive, NoConns(), tcpResponsive)
}

// detailedConnForAllRsp: constructs of all the connections domain
func detailedConnForAllRsp() *detailedConn {
	return newDetailedConn(allTCPconn(), AllConns().Subtract(allTCPconn()), AllConns())
}

// isAllObliviousRsp: returns true iff detailedConn contains all the connection domain
// (regardless of what part is responsive and what part isn't)
func (e *detailedConn) isAllObliviousRsp() bool {
	return e.allConn.Equal(connection.All())
}

// isEmpty: return true iff the detailedConn is empty
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
	return newDetailedConn(rspConn, otherConn, conn)
}

// subtract of two detailedConn: subtraction of tcpRspEnable, nonTCP and allConn
// (tcpRspDisable is computed based on these)
func (e *detailedConn) subtract(other *detailedConn) *detailedConn {
	rspConn := e.tcpRspEnable.Subtract(other.tcpRspEnable)
	otherConn := e.nonTCP.Subtract(other.nonTCP)
	conn := e.allConn.Subtract(other.allConn)
	return newDetailedConn(rspConn, otherConn, conn)
}

func (e *detailedConn) string() string {
	if !e.tcpRspDisable.IsEmpty() {
		return common.LongString(e.allConn) + " * "
	}
	return common.LongString(e.allConn)
}

// computeDetailedConn computes the detailedConn object, given input `srcToDst`
// that represents a src-to-dst connection, and `dstToSrc` that represents dst-to-src connection.
func computeDetailedConn(srcToDst, dstToSrc *connection.Set) *detailedConn {
	connTCP := srcToDst.Intersect(allTCPconn())
	if connTCP.IsEmpty() {
		return detailedConnForTCPRsp(NoConns(), srcToDst)
	}
	tcpSecondDirection := dstToSrc.Intersect(allTCPconn())
	// flip src/dst ports before intersection
	tcpSecondDirectionFlipped := tcpSecondDirection.SwapPorts()
	// tcp connection responsive subset
	return detailedConnForTCPRsp(connTCP.Intersect(tcpSecondDirectionFlipped), srcToDst)
}
