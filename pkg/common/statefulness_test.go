package common

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTCPConn(srcMinP, srcMaxP, dstMinP, dstMaxP int64) *ConnectionSet {
	res := NewConnectionSet(false)
	res.AddTCPorUDPConn(ProtocolTCP, srcMinP, srcMaxP, dstMinP, dstMaxP)
	return res
}

func newUDPConn(srcMinP, srcMaxP, dstMinP, dstMaxP int64) *ConnectionSet {
	res := NewConnectionSet(false)
	res.AddTCPorUDPConn(ProtocolUDP, srcMinP, srcMaxP, dstMinP, dstMaxP)
	return res
}

func newICMPconn() *ConnectionSet {
	res := NewConnectionSet(false)
	res.AddICMPConnection(MinICMPtype, MaxICMPtype, MinICMPcode, MaxICMPcode)
	return res
}

func allButTCP() *ConnectionSet {
	res := NewConnectionSet(true)
	tcpOnly := res.tcpConn()
	return res.Subtract(tcpOnly)
}

type statefulnessTest struct {
	name     string
	srcToDst *ConnectionSet
	dstToSrc *ConnectionSet
	// expectedIsStateful represents the expected IsStateful computed value for srcToDst,
	// which should be either StatefulTrue or StatefulFalse, given the input dstToSrc connection.
	// the computation applies only to the TCP protocol within those connections.
	expectedIsStateful int
	// expectedStatefulConn represents the subset from srcToDst which is not related to the "non-stateful" mark (*) on the srcToDst connection,
	// the stateless part for TCP is srcToDst.Subtract(statefuleConn)
	expectedStatefulConn *ConnectionSet
}

var testCasesStatefulness = []statefulnessTest{
	{
		name:                 "tcp_all_ports_on_both_directions",
		srcToDst:             newTCPConn(MinPort, MaxPort, MinPort, MaxPort), // TCP all ports
		dstToSrc:             newTCPConn(MinPort, MaxPort, MinPort, MaxPort), // TCP all ports
		expectedIsStateful:   StatefulTrue,
		expectedStatefulConn: newTCPConn(MinPort, MaxPort, MinPort, MaxPort), // TCP all ports
	},
	{
		name:     "first_all_cons_second_tcp_with_ports",
		srcToDst: NewConnectionSet(true),               // all connections
		dstToSrc: newTCPConn(80, 80, MinPort, MaxPort), // TCP , src-ports: 80, dst-ports: all

		// there is a subset of the tcp connection which is not stateful
		expectedIsStateful: StatefulFalse,

		// TCP src-ports: all, dst-port: 80 , union: all non-TCP conns
		expectedStatefulConn: allButTCP().Union(newTCPConn(MinPort, MaxPort, 80, 80)),
	},
	{
		name:                 "first_all_conns_second_no_tcp",
		srcToDst:             NewConnectionSet(true), // all connections
		dstToSrc:             newICMPconn(),          // ICMP
		expectedIsStateful:   StatefulFalse,
		expectedStatefulConn: allButTCP(), // UDP, ICMP (all TCP is considered stateless here)
	},
	{
		name:                 "tcp_with_ports_both_directions_exact_match",
		srcToDst:             newTCPConn(80, 80, 443, 443),
		dstToSrc:             newTCPConn(443, 443, 80, 80),
		expectedIsStateful:   StatefulTrue,
		expectedStatefulConn: newTCPConn(80, 80, 443, 443),
	},
	{
		name:                 "tcp_with_ports_both_directions_partial_match",
		srcToDst:             newTCPConn(80, 100, 443, 443),
		dstToSrc:             newTCPConn(443, 443, 80, 80),
		expectedIsStateful:   StatefulFalse,
		expectedStatefulConn: newTCPConn(80, 80, 443, 443),
	},
	{
		name:                 "tcp_with_ports_both_directions_no_match",
		srcToDst:             newTCPConn(80, 100, 443, 443),
		dstToSrc:             newTCPConn(80, 80, 80, 80),
		expectedIsStateful:   StatefulFalse,
		expectedStatefulConn: NewConnectionSet(false),
	},
	{
		name:                 "udp_and_tcp_with_ports_both_directions_no_match",
		srcToDst:             newTCPConn(80, 100, 443, 443).Union(newUDPConn(80, 100, 443, 443)),
		dstToSrc:             newTCPConn(80, 80, 80, 80).Union(newUDPConn(80, 80, 80, 80)),
		expectedIsStateful:   StatefulFalse,
		expectedStatefulConn: newUDPConn(80, 100, 443, 443),
	},
	{
		name:                 "no_tcp_in_first_direction",
		srcToDst:             newUDPConn(80, 100, 443, 443),
		dstToSrc:             newTCPConn(80, 80, 80, 80).Union(newUDPConn(80, 80, 80, 80)),
		expectedIsStateful:   StatefulTrue,
		expectedStatefulConn: newUDPConn(80, 100, 443, 443),
	},
	{
		name:                 "empty_conn_in_first_direction",
		srcToDst:             NewConnectionSet(false),
		dstToSrc:             newTCPConn(80, 80, 80, 80).Union(newUDPConn(MinPort, MaxPort, MinPort, MaxPort)),
		expectedIsStateful:   StatefulTrue,
		expectedStatefulConn: NewConnectionSet(false),
	},
	{
		name:     "only_udp_icmp_in_first_direction_and_empty_second_direction",
		srcToDst: newUDPConn(MinPort, MaxPort, MinPort, MaxPort).Union(newICMPconn()),
		dstToSrc: NewConnectionSet(false),
		// stateful analysis does not apply to udp/icmp, thus considered in the result as "stateful"
		// (to avoid marking it as stateless in the output)
		expectedIsStateful:   StatefulTrue,
		expectedStatefulConn: newUDPConn(MinPort, MaxPort, MinPort, MaxPort).Union(newICMPconn()),
	},
}

func (tt statefulnessTest) runTest(t *testing.T) {
	statefuleConn := tt.srcToDst.ConnectionWithStatefulness(tt.dstToSrc)
	require.Equal(t, tt.expectedIsStateful, tt.srcToDst.IsStateful)
	require.True(t, tt.expectedStatefulConn.Equal(statefuleConn))
}

func TestAll(t *testing.T) {
	// explainTests is the list of tests to run
	for testIdx := range testCasesStatefulness {
		tt := testCasesStatefulness[testIdx]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runTest(t)
		})
	}
	fmt.Println("done")
}
