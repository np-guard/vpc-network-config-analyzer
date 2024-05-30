/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
)

// VPCConnectivity holds detailed representation of allowed connectivity considering all resources in a vpc config1 instance
type VPCConnectivity struct {
	// computed for each layer separately its allowed connections (ingress and egress separately)
	// This is used for computing AllowedConns
	AllowedConnsPerLayer map[Node]map[string]*ConnectivityResult

	// computed for each node, by iterating its ConnectivityResult for all relevant VPC resources that capture it
	// a node is mapped to its set of  its allowed ingress (egress) communication as captured by
	// pairs of node+connection
	// This is auxiliary computation based on which AllowedConnsCombined is computed, however the "debug" format uses it
	AllowedConns map[Node]*ConnectivityResult

	// allowed connectivity combined and stateful
	// used by debug and json format only (at the moment)
	// For src node provides a map of dsts and the stateful connection it has to these dsts
	// note that subset of a non-stateful connection from AllowedConnsCombined can still be stateful
	// and as such add to this map

	AllowedConnsCombinedStateful GeneralStatefulConnectivityMap

	// grouped connectivity result
	GroupedConnectivity *GroupConnLines
}

// ConnectivityResult is used to capture allowed connectivity between Node elements
// A Node object has its associated ConnectivityResult (see VPCConnectivity.AllowedConns)
// The ConnectivityResult holds the allowed ingress and egress connections (to/from the associated node)
// with other Node objects and the connection attributes for each such node
type ConnectivityResult struct {
	IngressAllowedConns map[Node]*connection.Set
	EgressAllowedConns  map[Node]*connection.Set
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

// ConfigBasedConnectivityResults is used to capture allowed connectivity to/from elements in the vpc config1 (subnets / external ip-blocks)
// It is associated with a subnet when analyzing connectivity of subnets based on NACL resources
type ConfigBasedConnectivityResults struct {
	IngressAllowedConns map[VPCResourceIntf]*connection.Set
	EgressAllowedConns  map[VPCResourceIntf]*connection.Set
}

func NewConfigBasedConnectivityResults() *ConfigBasedConnectivityResults {
	return &ConfigBasedConnectivityResults{
		IngressAllowedConns: map[VPCResourceIntf]*connection.Set{},
		EgressAllowedConns:  map[VPCResourceIntf]*connection.Set{},
	}
}
