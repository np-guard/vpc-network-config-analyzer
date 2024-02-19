package common

import "github.com/np-guard/models/pkg/hypercubes"

const (
	// StatefulUnknown is the default value for a ConnectionSet object,
	StatefulUnknown int = iota
	// StatefulTrue represents a connection object for which any allowed TCP (on all allowed src/dst ports)
	// has an allowed response connection
	StatefulTrue
	// StatefulFalse represents a connection object for which there exists some allowed TCP
	// (on any allowed subset from the allowed src/dst ports) that does not have an allowed response connection
	StatefulFalse
)

// EnhancedString returns a connection string with possibly added asterisk for stateless connection
func (conn *ConnectionSet) EnhancedString() string {
	if conn.IsStateful == StatefulFalse {
		return conn.String() + " *"
	}
	return conn.String()
}

// ConnectionWithStatefulness updates `conn` object with `IsStateful` property, based on input `secondDirectionConn`.
// `conn` represents a src-to-dst connection, and `secondDirectionConn` represents dst-to-src connection.
// The property `IsStateful` of `conn` is set as `StatefulFalse` if there is at least some subset within TCP from `conn`
// which is not stateful (such that the response direction for this subset is not enabled).
// This function also returns a connection object with the exact subset of the stateful part (within TCP)
// from the entire connection `conn`, and with the original connections on other protocols.
func (conn *ConnectionSet) ConnectionWithStatefulness(secondDirectionConn *ConnectionSet) *ConnectionSet {
	connTCP := conn.tcpConn()
	if connTCP.IsEmpty() {
		conn.IsStateful = StatefulTrue
		return conn
	}
	secondDirectionConnTCP := secondDirectionConn.tcpConn()
	statefulCombinedConnTCP := connTCP.connTCPWithStatefulness(secondDirectionConnTCP)
	conn.IsStateful = connTCP.IsStateful
	nonTCP := conn.Subtract(connTCP)
	return nonTCP.Union(statefulCombinedConnTCP)
}

// connTCPWithStatefulness assumes that both `conn` and `secondDirectionConn` are within TCP.
// it assigns IsStateful a value within `conn`, and returns the subset from `conn` which is stateful.
func (conn *ConnectionSet) connTCPWithStatefulness(secondDirectionConn *ConnectionSet) *ConnectionSet {
	secondDirectionSwitchPortsDirection := secondDirectionConn.switchSrcDstPorts()
	// flip src/dst ports before intersection
	statefulCombinedConn := conn.Intersection(secondDirectionSwitchPortsDirection)
	if !conn.Equal(statefulCombinedConn) {
		conn.IsStateful = StatefulFalse
	} else {
		conn.IsStateful = StatefulTrue
	}
	return statefulCombinedConn
}

// tcpConn returns a new ConnectionSet object, which is the intersection of `conn` with TCP
func (conn *ConnectionSet) tcpConn() *ConnectionSet {
	res := NewConnectionSet(false)
	res.AddTCPorUDPConn(ProtocolTCP, MinPort, MaxPort, MinPort, MaxPort)
	return conn.Intersection(res)
}

// switchSrcDstPorts returns a new ConnectionSet object, built from the input ConnectionSet object.
// It assumes the input connection object is only within TCP protocol.
// For TCP the src and dst ports on relevant cubes are being switched.
func (conn *ConnectionSet) switchSrcDstPorts() *ConnectionSet {
	if conn.AllowAll || conn.IsEmpty() {
		return conn.Copy()
	}
	res := NewConnectionSet(false)
	cubes := conn.connectionProperties.GetCubesList()
	for _, cube := range cubes {
		protocols := cube[protocol]
		if protocols.Contains(TCP) {
			srcPorts := cube[srcPort]
			dstPorts := cube[dstPort]
			// if the entire domain is enabled by both src and dst no need to switch
			if !srcPorts.Equal(*getDimensionDomain(srcPort)) || !dstPorts.Equal(*getDimensionDomain(dstPort)) {
				newCube := copyCube(cube)
				newCube[srcPort], newCube[dstPort] = newCube[dstPort], newCube[srcPort]
				res.connectionProperties = res.connectionProperties.Union(hypercubes.CreateFromCube(newCube))
			} else {
				res.connectionProperties = res.connectionProperties.Union(hypercubes.CreateFromCube(cube))
			}
		}
	}
	return res
}
