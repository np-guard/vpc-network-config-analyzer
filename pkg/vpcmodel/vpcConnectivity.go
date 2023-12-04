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
	AllowedConnsCombined GeneralConnectivityMap

	// allowed connectivity combined and stateful
	AllowedConnsCombinedStateful GeneralConnectivityMap

	// grouped connectivity result
	GroupedConnectivity *GroupConnLines
}

// ConnectivityResult is used to capture allowed connectivity between Node elements
// A Node object has its associated ConnectivityResult (see VPCConnectivity.AllowedConns)
// The ConnectivityResult holds the allowed ingress and egress connections (to/from the associated node)
// with other Node objects and the connection attributes for each such node
type ConnectivityResult struct {
	IngressAllowedConns map[Node]*common.ConnectionSet
	EgressAllowedConns  map[Node]*common.ConnectionSet
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

// ConfigBasedConnectivityResults is used to capture allowed connectivity to/from elements in the vpc config1 (subnets / external ip-blocks)
// It is associated with a subnet when analyzing connectivity of subnets based on NACL resources
type ConfigBasedConnectivityResults struct {
	IngressAllowedConns map[VPCResourceIntf]*common.ConnectionSet
	EgressAllowedConns  map[VPCResourceIntf]*common.ConnectionSet
}

func NewConfigBasedConnectivityResults() *ConfigBasedConnectivityResults {
	return &ConfigBasedConnectivityResults{
		IngressAllowedConns: map[VPCResourceIntf]*common.ConnectionSet{},
		EgressAllowedConns:  map[VPCResourceIntf]*common.ConnectionSet{},
	}
}

func (v *VPCConnectivity) SplitAllowedConnsToUnidirectionalAndBidirectional() (
	bidirectional, unidirectional GeneralConnectivityMap) {
	unidirectional = GeneralConnectivityMap{}
	bidirectional = GeneralConnectivityMap{}
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

func (connectivityMap GeneralConnectivityMap) getAllowedConnForPair(src, dst VPCResourceIntf) *common.ConnectionSet {
	if connsMap, ok := connectivityMap[src]; ok {
		if conn, ok := connsMap[dst]; ok {
			return conn
		}
	}
	return NoConns()
}
