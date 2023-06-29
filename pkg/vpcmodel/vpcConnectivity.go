package vpcmodel

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// VPCConnectivity holds detailed representation of allowed connectivity considering all resources in a vpc config instance
type VPCConnectivity struct {
	// computed for each layer separately its allowed connections (ingress and egress separately)
	AllowedConnsPerLayer map[Node]map[string]*ConnectivityResult
	// computed for each node, by iterating its ConnectivityResult for all relevant VPC resources that capture it
	AllowedConns map[Node]*ConnectivityResult

	// combined connectivity - considering both ingress and egress per connection
	AllowedConnsCombined map[Node]map[Node]*common.ConnectionSet

	// allowed connectivity combined and stateful
	AllowedConnsCombinedStateful map[Node]map[Node]*common.ConnectionSet
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

// ConfigBasedConnectivityResults is used to capture allowed connectivity to/from elements in the vpc config (subnets / external ip-blocks)
// It is associated with a subnet when analyzing connectivity of subnets based on NACL resources
type ConfigBasedConnectivityResults struct {
	IngressAllowedConns map[string]*common.ConnectionSet
	EgressAllowedConns  map[string]*common.ConnectionSet
}

func NewConfigBasedConnectivityResults() *ConfigBasedConnectivityResults {
	return &ConfigBasedConnectivityResults{
		IngressAllowedConns: map[string]*common.ConnectionSet{},
		EgressAllowedConns:  map[string]*common.ConnectionSet{},
	}
}
