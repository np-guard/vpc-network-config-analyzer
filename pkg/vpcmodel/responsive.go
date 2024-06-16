/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package vpcmodel

import (
	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/netp"
)

func newTCPSet() *connection.Set {
	return connection.TCPorUDPConnection(netp.ProtocolStringTCP, connection.MinPort, connection.MaxPort,
		connection.MinPort, connection.MaxPort)
}

// PartitionTCPNonTCP given a connection returns its TCP and non-TCP sub-connections
func partitionTCPNonTCP(conn *connection.Set) (tcp, nonTCP *connection.Set) {
	tcpFractionOfConn := newTCPSet().Intersect(conn)
	nonTCPFractionOfConn := conn.Subtract(tcpFractionOfConn)
	return tcpFractionOfConn, nonTCPFractionOfConn
}

// getResponsiveConn returns  connection object with the exact the responsive part within TCP
// and with the original connections on other protocols.
// `srcToDst` represents a src-to-dst connection, and `dstToSrc` represents dst-to-src connection.
func getResponsiveConn(srcToDst *connection.Set, dstToSrc *connection.Set) *connection.Set {
	connTCP := srcToDst.Intersect(newTCPSet())
	if connTCP.IsEmpty() {
		return srcToDst
	}
	tcpSecondDirection := dstToSrc.Intersect(newTCPSet())
	// flip src/dst ports before intersection
	tcpSecondDirectionFlipped := tcpSecondDirection.SwitchSrcDstPorts()
	// tcp connection stateful subset
	statefulCombinedConnTCP := connTCP.Intersect(tcpSecondDirectionFlipped)
	return srcToDst.Subtract(connTCP).Union(statefulCombinedConnTCP)
}

// getResponsiveConn returns connection object with the exact the responsive part within TCP
// `srcToDst` represents a src-to-dst connection, and `dstToSrc` represents dst-to-src connection.
func getTCPResponsiveConn(srcToDst *connection.Set, dstToSrc *connection.Set) *connection.Set {
	connTCP := srcToDst.Intersect(newTCPSet())
	if connTCP.IsEmpty() {
		return srcToDst
	}
	tcpSecondDirection := dstToSrc.Intersect(newTCPSet())
	// flip src/dst ports before intersection
	tcpSecondDirectionFlipped := tcpSecondDirection.SwitchSrcDstPorts()
	// tcp connection responsive subset
	return connTCP.Intersect(tcpSecondDirectionFlipped)
}
