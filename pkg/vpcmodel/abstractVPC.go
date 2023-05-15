package vpcmodel

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

type NamedResourceIntf interface {
	UID() string
	Name() string
}

type NamedResource struct {
	ResourceName string
	ResourceUID  string
}

func (n *NamedResource) Name() string {
	return n.ResourceName
}

func (n *NamedResource) UID() string {
	return n.ResourceUID
}

///////////////////////////vpc resources////////////////////////////////////////////////////////////////////////////

// Node is the basic endpoint element in the connectivity graph [ network interface , reserved ip, external cidrs]

type Node interface {
	NamedResourceIntf
	Cidr() string
	IsInternal() bool
	IsPublicInternet() bool
	Details() string
	DetailsMap() map[string]string
	Kind() string
}

// NodeSet is an element that may capture several nodes [vpc ,subnet, vsi, (service network?)]
type NodeSet interface {
	NamedResourceIntf
	Nodes() []Node
	Connectivity() *ConnectivityResult
	Details() string
	DetailsMap() map[string]string
	Kind() string
}

// FilterTrafficResource capture allowed traffic between 2 endpoints
type FilterTrafficResource interface {
	NamedResourceIntf
	// get the connectivity result when the filterTraffic resource is applied to the given NodeSet element
	AllowedConnectivity(src, dst Node, isIngress bool) *common.ConnectionSet
	Kind() string
	ReferencedIPblocks() []*common.IPBlock
	Details() []string
	DetailsMap() []map[string]string
	ConnectivityMap() map[string]*IPbasedConnectivityResult
}

// routing resource enables connectivity from src to destination via that resource
// fip, pgw, vpe
type RoutingResource interface {
	NamedResourceIntf
	Src() []Node
	Destinations() []Node
	AllowedConnectivity(src, dst Node) *common.ConnectionSet
	Details() string
	DetailsMap() map[string]string
	Kind() string
	ConnectivityMap() map[string]ConfigBasedConnectivityResults
}
