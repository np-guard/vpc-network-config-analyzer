/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package vpcmodel

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/netp"
)

func newUDPConn(t *testing.T, srcMinP, srcMaxP, dstMinP, dstMaxP int64) *connection.Set {
	t.Helper()
	return connection.TCPorUDPConnection(netp.ProtocolStringUDP, srcMinP, srcMaxP, dstMinP, dstMaxP)
}

func newICMPconn(t *testing.T) *connection.Set {
	t.Helper()
	return connection.ICMPConnection(
		connection.MinICMPType, connection.MaxICMPType,
		connection.MinICMPCode, connection.MaxICMPCode)
}

func newTCPUDPSet(t *testing.T, p netp.ProtocolString) *connection.Set {
	t.Helper()
	return connection.TCPorUDPConnection(p,
		connection.MinPort, connection.MaxPort,
		connection.MinPort, connection.MaxPort)
}

type responsiveTest struct {
	name     string
	srcToDst *connection.Set
	dstToSrc *connection.Set
	// expectedResponsiveConn represents the subset from srcToDst which is not related to the
	// "non-responsive" mark (*) on the srcToDst connection,
	expectedResponsiveConn *connection.Set
}

func (tt responsiveTest) runTest(t *testing.T) {
	t.Helper()
	responsiveConn := getTCPResponsiveConn(tt.srcToDst, tt.dstToSrc)
	require.True(t, tt.expectedResponsiveConn.Equal(responsiveConn))
}

func TestAll(t *testing.T) {
	var testCasesResponsive = []responsiveTest{
		{
			name:                   "tcp_all_ports_on_both_directions",
			srcToDst:               newTCPUDPSet(t, netp.ProtocolStringTCP), // TCP all ports
			dstToSrc:               newTCPUDPSet(t, netp.ProtocolStringTCP), // TCP all ports
			expectedResponsiveConn: newTCPUDPSet(t, netp.ProtocolStringTCP), // TCP all ports
		},
		{
			name:     "first_all_cons_second_tcp_with_ports",
			srcToDst: connection.All(),                                           // all connections
			dstToSrc: newTCPConn(80, 80, connection.MinPort, connection.MaxPort), // TCP , src-ports: 80, dst-ports: all

			// TCP src-ports: all, dst-port: 80
			expectedResponsiveConn: newTCPConn(connection.MinPort, connection.MaxPort, 80, 80),
		},
		{
			name:     "first_all_conns_second_no_tcp",
			srcToDst: connection.All(), // all connections
			dstToSrc: newICMPconn(t),   // ICMP
			// connection.None() (all TCP is considered stateless here)
			expectedResponsiveConn: connection.None(),
		},
		{
			name:                   "tcp_with_ports_both_directions_exact_match",
			srcToDst:               newTCPConn(80, 80, 443, 443),
			dstToSrc:               newTCPConn(443, 443, 80, 80),
			expectedResponsiveConn: newTCPConn(80, 80, 443, 443),
		},
		{
			name:                   "tcp_with_ports_both_directions_partial_match",
			srcToDst:               newTCPConn(80, 100, 443, 443),
			dstToSrc:               newTCPConn(443, 443, 80, 80),
			expectedResponsiveConn: newTCPConn(80, 80, 443, 443),
		},
		{
			name:                   "tcp_with_ports_both_directions_no_match",
			srcToDst:               newTCPConn(80, 100, 443, 443),
			dstToSrc:               newTCPConn(80, 80, 80, 80),
			expectedResponsiveConn: connection.None(),
		},
		{
			name:                   "udp_and_tcp_with_ports_both_directions_no_match",
			srcToDst:               newTCPConn(80, 100, 443, 443).Union(newUDPConn(t, 80, 100, 443, 443)),
			dstToSrc:               newTCPConn(80, 80, 80, 80).Union(newUDPConn(t, 80, 80, 80, 80)),
			expectedResponsiveConn: connection.None(),
		},
		{
			name:                   "no_tcp_in_first_direction",
			srcToDst:               newUDPConn(t, 70, 100, 443, 443),
			dstToSrc:               newTCPConn(70, 80, 80, 80).Union(newUDPConn(t, 70, 80, 80, 80)),
			expectedResponsiveConn: connection.None(),
		},
		{
			name:                   "empty_conn_in_first_direction",
			srcToDst:               connection.None(),
			dstToSrc:               newTCPConn(80, 80, 80, 80).Union(newTCPUDPSet(t, netp.ProtocolStringUDP)),
			expectedResponsiveConn: connection.None(),
		},
		{
			name:     "only_udp_icmp_in_first_direction_and_empty_second_direction",
			srcToDst: newTCPUDPSet(t, netp.ProtocolStringUDP).Union(newICMPconn(t)),
			dstToSrc: connection.None(),
			// responsive analysis does not apply to udp/icmp, thus TCP responsive component is empty
			expectedResponsiveConn: connection.None(),
		},
	}
	t.Parallel()
	// explainTests is the list of tests to run
	for testIdx := range testCasesResponsive {
		tt := testCasesResponsive[testIdx]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runTest(t)
		})
	}
}
