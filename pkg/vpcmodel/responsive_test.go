/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package vpcmodel

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
)

type responsiveTest struct {
	name     string
	srcToDst *netset.TransportSet
	dstToSrc *netset.TransportSet
	// expectedTCPResponsiveConn represents the subset from srcToDst which is not related to the
	// "non-responsive" mark (*) on the srcToDst connection,
	expectedTCPResponsiveConn    *netset.TransportSet
	expectedTCPNonResponsiveConn *netset.TransportSet
	expectedAllConn              *netset.TransportSet
}

func (tt responsiveTest) runTest(t *testing.T) {
	t.Helper()
	detailedConn := computeDetailedConn(tt.srcToDst, tt.dstToSrc)
	require.True(t, tt.expectedTCPResponsiveConn.Equal(detailedConn.tcpRspEnable))
	require.True(t, tt.expectedTCPNonResponsiveConn.Equal(detailedConn.TCPRspDisable))
	require.True(t, tt.expectedAllConn.Equal(detailedConn.allConn))
}

func TestAll(t *testing.T) {
	var testCasesResponsive = []responsiveTest{
		{
			name:                         "tcp_all_ports_on_both_directions",
			srcToDst:                     newTCPUDPSet(netp.ProtocolStringTCP), // TCP all ports
			dstToSrc:                     newTCPUDPSet(netp.ProtocolStringTCP), // TCP all ports
			expectedTCPResponsiveConn:    newTCPUDPSet(netp.ProtocolStringTCP), // TCP all ports
			expectedTCPNonResponsiveConn: netset.NoTransports(),
			expectedAllConn:              newTCPUDPSet(netp.ProtocolStringTCP),
		},
		{
			name:     "first_all_cons_second_tcp_with_ports",
			srcToDst: netset.AllTransports(),                         // all connections
			dstToSrc: newTCPConn(80, 80, netp.MinPort, netp.MaxPort), // TCP , src-ports: 80, dst-ports: all

			// TCP src-ports: all, dst-port: 80
			expectedTCPResponsiveConn: newTCPConn(netp.MinPort, netp.MaxPort, 80, 80),
			expectedTCPNonResponsiveConn: allTCPconn().Subtract(newTCPConn(netp.MinPort,
				netp.MaxPort, 80, 80)),
			expectedAllConn: netset.AllTransports(),
		},
		{
			name:                         "first_all_conns_second_no_tcp",
			srcToDst:                     netset.AllTransports(), // all connections
			dstToSrc:                     newICMPconn(),          // ICMP
			expectedTCPResponsiveConn:    netset.NoTransports(),
			expectedTCPNonResponsiveConn: allTCPconn(),
			expectedAllConn:              netset.AllTransports(),
		},
		{
			name:                         "tcp_with_ports_both_directions_exact_match",
			srcToDst:                     newTCPConn(80, 80, 443, 443),
			dstToSrc:                     newTCPConn(443, 443, 80, 80),
			expectedTCPResponsiveConn:    newTCPConn(80, 80, 443, 443),
			expectedTCPNonResponsiveConn: netset.NoTransports(),
			expectedAllConn:              newTCPConn(80, 80, 443, 443),
		},
		{
			name:                         "tcp_with_ports_both_directions_partial_match",
			srcToDst:                     newTCPConn(80, 100, 443, 443),
			dstToSrc:                     newTCPConn(443, 443, 80, 80),
			expectedTCPResponsiveConn:    newTCPConn(80, 80, 443, 443),
			expectedTCPNonResponsiveConn: newTCPConn(81, 100, 443, 443),
			expectedAllConn:              newTCPConn(80, 100, 443, 443),
		},
		{
			name:                         "tcp_with_ports_both_directions_no_match",
			srcToDst:                     newTCPConn(80, 100, 443, 443),
			dstToSrc:                     newTCPConn(80, 80, 80, 80),
			expectedTCPResponsiveConn:    netset.NoTransports(),
			expectedTCPNonResponsiveConn: newTCPConn(80, 100, 443, 443),
			expectedAllConn:              newTCPConn(80, 100, 443, 443),
		},
		{
			name:                         "udp_and_tcp_with_ports_both_directions_no_match",
			srcToDst:                     newTCPConn(80, 100, 443, 443).Union(newUDPConn(80, 100, 443, 443)),
			dstToSrc:                     newTCPConn(80, 80, 80, 80).Union(newUDPConn(80, 80, 80, 80)),
			expectedTCPResponsiveConn:    netset.NoTransports(),
			expectedTCPNonResponsiveConn: newTCPConn(80, 100, 443, 443),
			expectedAllConn:              newTCPConn(80, 100, 443, 443).Union(newUDPConn(80, 100, 443, 443)),
		},
		{
			name:                         "no_tcp_in_first_direction",
			srcToDst:                     newUDPConn(70, 100, 443, 443),
			dstToSrc:                     newTCPConn(70, 80, 80, 80).Union(newUDPConn(70, 80, 80, 80)),
			expectedTCPResponsiveConn:    netset.NoTransports(),
			expectedTCPNonResponsiveConn: netset.NoTransports(),
			expectedAllConn:              newUDPConn(70, 100, 443, 443),
		},
		{
			name:                         "empty_conn_in_first_direction",
			srcToDst:                     netset.NoTransports(),
			dstToSrc:                     newTCPConn(80, 80, 80, 80).Union(newTCPUDPSet(netp.ProtocolStringUDP)),
			expectedTCPResponsiveConn:    netset.NoTransports(),
			expectedTCPNonResponsiveConn: netset.NoTransports(),
			expectedAllConn:              netset.NoTransports(),
		},
		{
			name:     "only_udp_icmp_in_first_direction_and_empty_second_direction",
			srcToDst: newTCPUDPSet(netp.ProtocolStringUDP).Union(newICMPconn()),
			dstToSrc: netset.NoTransports(),
			// responsive analysis does not apply to udp/icmp, thus TCP responsive component is empty
			expectedTCPResponsiveConn:    netset.NoTransports(),
			expectedTCPNonResponsiveConn: netset.NoTransports(),
			expectedAllConn:              newTCPUDPSet(netp.ProtocolStringUDP).Union(newICMPconn()),
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
