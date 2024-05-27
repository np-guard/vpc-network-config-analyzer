package vpcmodel

import (
	"github.com/np-guard/models/pkg/connection"
)

// todo: remove stateful from connection.Set (for both options)

// ExtendedSet connection details
type ExtendedSet struct {
	connection     *connection.Set // connection between <src, dst>
	connectionBack *connection.Set // reply connection (subseteq connection)
}

func (e *ExtendedSet) String() []string {
	return nil
}

// ExtendedSetOption2 connection details
type ExtendedSetOption2 struct {
	// todo: for this option remove stateful from connection.Set
	statefulConn    *connection.Set // connection between <src, dst>
	nonStatefulConn *connection.Set // reply connection (subseteq connection)
}

func (e *ExtendedSetOption2) String() []string {
	return nil
}

// ConnectivityResultNew is used to capture allowed connectivity between Node elements
// A Node object has its associated ConnectivityResult (see VPCConnectivity.AllowedConns)
// The ConnectivityResult holds the allowed ingress and egress connections (to/from the associated node)
// with other Node objects and the connection attributes for each such node
// todo rename to ConnectivityResult
type ConnectivityResultNew struct {
	IngressAllowedConns map[Node]*ExtendedSet
	EgressAllowedConns  map[Node]*ExtendedSet
}

// GeneralConnectivityMapNew describes connectivity
// todo: rename to GeneralConnectivityMap
type GeneralConnectivityMapNew map[VPCResourceIntf]map[VPCResourceIntf]*ExtendedSet
