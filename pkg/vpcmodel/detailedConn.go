/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"strings"

	"github.com/np-guard/models/pkg/netset"
	common "github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

const asterisk = " * "

// detailedConn captures the connection with TCP's responsiveness details, as described below.
// It is created from src-to-dest allowed connection (TCP and non-TCP) and allowed response
// connection dest-to-src.

// Note that allowed response connection differs from the allowed dest-to-src connection.
// Specifically, this is relevant when in response to a TCP src to dst connection, dest initiates a dst to src response.

// Further entities of the connection may be created from operations as union e.g. for abstraction
// note: TCPRspDisable is not independent and is calculated based on the other properties;
// it is kept since it is widely used - to determine if the connection is responsive
type detailedConn struct {
	tcpRspEnable  *netset.TransportSet // responsive TCP connection between <src, dst>
	nonTCP        *netset.TransportSet // non TCP connection (for which responsiveness is non-relevant)
	allConn       *netset.TransportSet // entire connection
	TCPRspDisable *netset.TransportSet // non-responsive TCP connection between <src, dst>; complementary of tcpRspEnable
	// connection is defined to be responsive if nonTCP is empty
}

// operation on detailedConn
// The operations are performed on the disjoint tcpRspEnable and nonTCP and on allConn which contains them;
// TCPRspDisable - the tcp complementary of tcpRspEnable w.r.t. allConn -
// is computed as allConn minus (tcpRspEnable union nonTCP)

func newDetailedConn(tspRspConn, otherConn, allConn *netset.TransportSet) *detailedConn {
	return &detailedConn{
		tcpRspEnable:  tspRspConn,
		TCPRspDisable: (allConn.Subtract(otherConn)).Subtract(tspRspConn),
		nonTCP:        otherConn,
		allConn:       allConn,
	}
}

func emptyDetailedConn() *detailedConn {
	return newDetailedConn(NoConns(), NoConns(), NoConns())
}

// detailedConnForTCPRsp returns a new detailedConn from input TCP responsive connection and the entire connection objects
func detailedConnForTCPRsp(tcpResponsive, allConn *netset.TransportSet) *detailedConn {
	_, nonTCPFraction := partitionTCPNonTCP(allConn)
	return newDetailedConn(tcpResponsive, nonTCPFraction, allConn)
}

// detailedConnForResponsive: is given the tcp responsive conn, assuming there is only
// a tcp responsive component in the connection
func detailedConnForResponsive(tcpResponsive *netset.TransportSet) *detailedConn {
	return newDetailedConn(tcpResponsive, NoConns(), tcpResponsive)
}

// detailedConnForAllRsp: constructs of all the connections domain
func detailedConnForAllRsp() *detailedConn {
	return newDetailedConn(allTCPconn(), AllConns().Subtract(allTCPconn()), AllConns())
}

// isAllObliviousRsp: returns true iff detailedConn contains all the connection domain
// (regardless of what part is responsive and what part isn't)
func (d *detailedConn) isAllObliviousRsp() bool {
	return d.allConn.Equal(netset.AllTransports())
}

// isEmpty: return true iff the detailedConn is empty
func (d *detailedConn) isEmpty() bool {
	return d.allConn.IsEmpty()
}

// Equal all components of two detailedConn are equal
func (d *detailedConn) equal(other *detailedConn) bool {
	return d.tcpRspEnable.Equal(other.tcpRspEnable) && d.nonTCP.Equal(other.nonTCP) &&
		d.allConn.Equal(other.allConn)
}

// union of two detailedConn: union tcpRspEnable, nonTCP and allConn
// (TCPRspDisable is computed based on these)
func (d *detailedConn) union(other *detailedConn) *detailedConn {
	rspConn := d.tcpRspEnable.Union(other.tcpRspEnable)
	otherConn := d.nonTCP.Union(other.nonTCP)
	conn := d.allConn.Union(other.allConn)
	return newDetailedConn(rspConn, otherConn, conn)
}

// subtract of two detailedConn: subtraction of tcpRspEnable, nonTCP and allConn
// (TCPRspDisable is computed based on these)
func (d *detailedConn) subtract(other *detailedConn) *detailedConn {
	rspConn := d.tcpRspEnable.Subtract(other.tcpRspEnable)
	otherConn := d.nonTCP.Subtract(other.nonTCP)
	conn := d.allConn.Subtract(other.allConn)
	return newDetailedConn(rspConn, otherConn, conn)
}

func (d *detailedConn) hasTCPComponent() bool {
	return !d.tcpRspEnable.Union(d.TCPRspDisable).IsEmpty()
}

// returns the tcp responsive and non-tcp component
func (d *detailedConn) nonTCPAndResponsiveTCPComponent() *netset.TransportSet {
	return d.tcpRspEnable.Union(d.nonTCP)
}

// string adds * to non-responsive TCP components of the connection
// for cosmetic reasons remove the protocol word from cubes prints
func (d *detailedConn) string() string { ////////////////////olaaaaaaaaaaaaaa
	if d.allConn.IsEmpty() {
		return common.LongString(d.allConn)
	}
	resStrSlice := []string{}
	if !d.TCPRspDisable.IsEmpty() {
		tcpNonResponsive := common.LongString(d.TCPRspDisable)
		tcpNonResponsive = strings.ReplaceAll(tcpNonResponsive, ";", asterisk+";")
		resStrSlice = append(resStrSlice, tcpNonResponsive+asterisk)
	}
	if !d.nonTCPAndResponsiveTCPComponent().IsEmpty() {
		resStrSlice = append(resStrSlice, common.LongString(d.nonTCPAndResponsiveTCPComponent()))
	}
	// todo: remove "protocol" from the original cube printing funcs
	return strings.ReplaceAll(strings.Join(resStrSlice, "; "), "protocol: ", "")
}

// in the structs a single line represents connection of each <src, dst>
// in the reports we print potentially two lines for each <src, dst> connection:
// one for the "main" tcp responsive + non tcp component and the other for the tcp non-responsive component
// this separation is done here: the former is returned for bidirectional and the latter for false
func (d *detailedConn) connStrPerConnectionType(nonTCPAndResponsiveTCP bool) string {
	if nonTCPAndResponsiveTCP {
		return common.LongString(d.nonTCPAndResponsiveTCPComponent())
	}
	return common.LongString(d.TCPRspDisable) + asterisk
}

// computeDetailedConn computes the detailedConn object, given input `srcToDst`
// that represents a src-to-dst connection, and `dstToSrc` that represents dst-to-src connection.
func computeDetailedConn(srcToDst, dstToSrc *netset.TransportSet) *detailedConn {
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
