/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"github.com/np-guard/models/pkg/netset"
)

// VPCConnectivity holds detailed representation of allowed connectivity considering all resources in a vpc config1 instance
type VPCConnectivity struct {
	// computed for each layer separately its allowed connections (ingress and egress separately)
	// This is used for computing AllowedConns
	AllowedConnsPerLayer map[Node]map[string]*ConnectivityResult

	// allowed connectivity combined and responsive
	// used by json format only (at the moment)
	// For src node provides a map of dsts and the responsive connection it has to these dsts
	// note that subset of a non-responsive connection from AllowedConnsCombined can still be responsive
	// and as such add to this map

	AllowedConnsCombinedResponsive GeneralResponsiveConnectivityMap

	// grouped connectivity result
	GroupedConnectivity *GroupConnLines
}

// ConnectivityResult is used to capture allowed connectivity between Node elements
// A Node object has its associated ConnectivityResult (see VPCConnectivity.AllowedConns)
// The ConnectivityResult holds the allowed ingress and egress connections (to/from the associated node)
// with other Node objects and the connection attributes for each such node
type ConnectivityResult struct {
	IngressAllowedConns map[Node]*netset.TransportSet
	EgressAllowedConns  map[Node]*netset.TransportSet
}

func (cr *ConnectivityResult) ingressOrEgressAllowedConns(isIngress bool) map[Node]*netset.TransportSet {
	if isIngress {
		return cr.IngressAllowedConns
	}
	return cr.EgressAllowedConns
}

// IPbasedConnectivityResult is used to capture allowed connectivity to/from ip-blocks (vpc internal/external)
// It is associated with a subnet when analyzing connectivity of subnets based on NACL resources
// (see func (nl *NaclLayer) ConnectivityMap() )
type IPbasedConnectivityResult struct {
	IngressAllowedConns map[*netset.IPBlock]*netset.TransportSet
	EgressAllowedConns  map[*netset.IPBlock]*netset.TransportSet
}

// ConfigBasedConnectivityResults is used to capture allowed connectivity to/from elements in the vpc config1 (subnets / external ip-blocks)
// It is associated with a subnet when analyzing connectivity of subnets based on NACL resources
type ConfigBasedConnectivityResults struct {
	IngressAllowedConns map[VPCResourceIntf]*netset.TransportSet
	EgressAllowedConns  map[VPCResourceIntf]*netset.TransportSet
}

func NewConfigBasedConnectivityResults() *ConfigBasedConnectivityResults {
	return &ConfigBasedConnectivityResults{
		IngressAllowedConns: map[VPCResourceIntf]*netset.TransportSet{},
		EgressAllowedConns:  map[VPCResourceIntf]*netset.TransportSet{},
	}
}
