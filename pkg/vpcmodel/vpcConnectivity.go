package vpcmodel

import (
	connection "github.com/np-guard/connectionlib/pkg/connection"
	ipblock "github.com/np-guard/connectionlib/pkg/ipblock"
)

// VPCConnectivity holds detailed representation of allowed connectivity considering all resources in a vpc config instance
type VPCConnectivity struct {
	// computed for each layer separately its allowed connections (ingress and egress separately)
	AllowedConnsPerLayer map[Node]map[string]*ConnectivityResult
	// computed for each node, by iterating its ConnectivityResult for all relevant VPC resources that capture it
	AllowedConns map[Node]*ConnectivityResult

	// combined connectivity - considering both ingress and egress per connection
	AllowedConnsCombined NodesConnectionsMap

	// allowed connectivity combined and stateful
	AllowedConnsCombinedStateful NodesConnectionsMap

	// grouped connectivity result
	GroupedConnectivity *GroupConnLines
}

type NodesConnectionsMap map[Node]map[Node]*connection.Set

func NewNodesConnectionsMap() NodesConnectionsMap {
	return NodesConnectionsMap{}
}

// ConnectivityResult is used to capture allowed connectivity between Node elements
// A Node object has its associated ConnectivityResult (see VPCConnectivity.AllowedConns)
// The ConnectivityResult holds the allowed ingress and egress connections (to/from the associated node)
// with other Node objects and the connection attributes for each such node
type ConnectivityResult struct {
	IngressAllowedConns map[Node]*connection.Set
	EgressAllowedConns  map[Node]*connection.Set
}

// NewConnectivityResult returns a new (empty) ConnectivityResult object
func NewConnectivityResult() *ConnectivityResult {
	return &ConnectivityResult{
		IngressAllowedConns: map[Node]*connection.Set{},
		EgressAllowedConns:  map[Node]*connection.Set{},
	}
}

func (cr *ConnectivityResult) ingressOrEgressAllowedConns(isIngress bool) map[Node]*connection.Set {
	if isIngress {
		return cr.IngressAllowedConns
	}
	return cr.EgressAllowedConns
}

// IPbasedConnectivityResult is used to capture allowed connectivity to/from ip-blocks (vpc internal/external)
// It is associated with a subnet when analyzing connectivity of subnets based on NACL resources
// (see func (nl *NaclLayer) ConnectivityMap() )
type IPbasedConnectivityResult struct {
	IngressAllowedConns map[*ipblock.IPBlock]*connection.Set
	EgressAllowedConns  map[*ipblock.IPBlock]*connection.Set
}

func NewIPbasedConnectivityResult() *IPbasedConnectivityResult {
	return &IPbasedConnectivityResult{
		IngressAllowedConns: map[*ipblock.IPBlock]*connection.Set{},
		EgressAllowedConns:  map[*ipblock.IPBlock]*connection.Set{},
	}
}

// ConfigBasedConnectivityResults is used to capture allowed connectivity to/from elements in the vpc config (subnets / external ip-blocks)
// It is associated with a subnet when analyzing connectivity of subnets based on NACL resources
type ConfigBasedConnectivityResults struct {
	IngressAllowedConns map[EndpointElem]*connection.Set
	EgressAllowedConns  map[EndpointElem]*connection.Set
}

func NewConfigBasedConnectivityResults() *ConfigBasedConnectivityResults {
	return &ConfigBasedConnectivityResults{
		IngressAllowedConns: map[EndpointElem]*connection.Set{},
		EgressAllowedConns:  map[EndpointElem]*connection.Set{},
	}
}

func (v *VPCConnectivity) SplitAllowedConnsToUnidirectionalAndBidirectional() (
	bidirectional, unidirectional NodesConnectionsMap) {
	unidirectional = NewNodesConnectionsMap()
	bidirectional = NewNodesConnectionsMap()
	for src, connsMap := range v.AllowedConnsCombined {
		for dst, conn := range connsMap {
			if conn.IsEmpty() {
				continue
			}
			statefulConn := v.AllowedConnsCombinedStateful.getAllowedConnForPair(src, dst)
			switch {
			case conn.Equal(statefulConn):
				bidirectional.updateAllowedConnsMap(src, dst, conn)
			case statefulConn.IsEmpty():
				unidirectional.updateAllowedConnsMap(src, dst, conn)
			default:
				bidirectional.updateAllowedConnsMap(src, dst, statefulConn)
				unidirectional.updateAllowedConnsMap(src, dst, conn.Subtract(statefulConn))
			}
		}
	}
	return bidirectional, unidirectional
}

func (nodesConnMap NodesConnectionsMap) updateAllowedConnsMap(src, dst Node, conn *connection.Set) {
	if _, ok := nodesConnMap[src]; !ok {
		nodesConnMap[src] = map[Node]*connection.Set{}
	}
	nodesConnMap[src][dst] = conn
}

func (nodesConnMap NodesConnectionsMap) getAllowedConnForPair(src, dst Node) *connection.Set {
	if connsMap, ok := nodesConnMap[src]; ok {
		if conn, ok := connsMap[dst]; ok {
			return conn
		}
	}
	return NoConns()
}
