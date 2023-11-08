package vpcmodel

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// VPCConnectivity holds detailed representation of allowed connectivity considering all resources in a vpc config1 instance
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

type NodesConnectionsMap map[Node]map[Node]*common.ConnectionSet

func NewNodesConnectionsMap() NodesConnectionsMap {
	return NodesConnectionsMap{}
}

// ConnectivityResult is used to capture allowed connectivity between Node elements
// A Node object has its associated ConnectivityResult (see VPCConnectivity.AllowedConns)
// The ConnectivityResult holds the allowed ingress and egress connections (to/from the associated node)
// with other Node objects and the connection attributes for each such node
type ConnectivityResult struct {
	IngressAllowedConns map[Node]*common.ConnectionSet
	EgressAllowedConns  map[Node]*common.ConnectionSet
}

// NewConnectivityResult returns a new (empty) ConnectivityResult object
func NewConnectivityResult() *ConnectivityResult {
	return &ConnectivityResult{
		IngressAllowedConns: map[Node]*common.ConnectionSet{},
		EgressAllowedConns:  map[Node]*common.ConnectionSet{},
	}
}

func (cr *ConnectivityResult) ingressOrEgressAllowedConns(isIngress bool) map[Node]*common.ConnectionSet {
	if isIngress {
		return cr.IngressAllowedConns
	}
	return cr.EgressAllowedConns
}

// IPbasedConnectivityResult is used to capture allowed connectivity to/from ip-blocks (vpc internal/external)
// It is associated with a subnet when analyzing connectivity of subnets based on NACL resources
// (see func (nl *NaclLayer) ConnectivityMap() )
type IPbasedConnectivityResult struct {
	IngressAllowedConns map[*common.IPBlock]*common.ConnectionSet
	EgressAllowedConns  map[*common.IPBlock]*common.ConnectionSet
}

func NewIPbasedConnectivityResult() *IPbasedConnectivityResult {
	return &IPbasedConnectivityResult{
		IngressAllowedConns: map[*common.IPBlock]*common.ConnectionSet{},
		EgressAllowedConns:  map[*common.IPBlock]*common.ConnectionSet{},
	}
}

// ConfigBasedConnectivityResults is used to capture allowed connectivity to/from elements in the vpc config1 (subnets / external ip-blocks)
// It is associated with a subnet when analyzing connectivity of subnets based on NACL resources
type ConfigBasedConnectivityResults struct {
	IngressAllowedConns map[EndpointElem]*common.ConnectionSet
	EgressAllowedConns  map[EndpointElem]*common.ConnectionSet
}

func NewConfigBasedConnectivityResults() *ConfigBasedConnectivityResults {
	return &ConfigBasedConnectivityResults{
		IngressAllowedConns: map[EndpointElem]*common.ConnectionSet{},
		EgressAllowedConns:  map[EndpointElem]*common.ConnectionSet{},
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

func (nodesConnMap NodesConnectionsMap) updateAllowedConnsMap(src, dst Node, conn *common.ConnectionSet) {
	if _, ok := nodesConnMap[src]; !ok {
		nodesConnMap[src] = map[Node]*common.ConnectionSet{}
	}
	nodesConnMap[src][dst] = conn
}

func (nodesConnMap NodesConnectionsMap) getAllowedConnForPair(src, dst Node) *common.ConnectionSet {
	if connsMap, ok := nodesConnMap[src]; ok {
		if conn, ok := connsMap[dst]; ok {
			return conn
		}
	}
	return NoConns()
}
