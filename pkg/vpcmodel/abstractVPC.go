package vpcmodel

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// VPCResourceIntf captures common properties for VPC resources
type VPCResourceIntf interface {
	UID() string
	Name() string
	ZoneName() string
	Kind() string

	DrawioResourceIntf
}

// VPCResource implements part of the VPCResourceIntf
// every concrete resource type should contain VPCResource and also implement the DrawioResourceIntf
type VPCResource struct {
	ResourceName string
	ResourceUID  string
	ResourceType string
	Zone         string
}

func (n *VPCResource) Name() string {
	return n.ResourceName
}

func (n *VPCResource) UID() string {
	return n.ResourceUID
}
func (n *VPCResource) ZoneName() string {
	return n.Zone
}

func (n *VPCResource) Kind() string {
	return n.ResourceType
}

func (n *VPCResource) IsExternal() bool {
	return false
}

const (
	// filter-resources layer names (grouping all vpc resources of that kind)
	NaclLayer          = "NaclLayer"
	SecurityGroupLayer = "SecurityGroupLayer"
)

///////////////////////////vpc resources////////////////////////////////////////////////////////////////////////////

// Node is the basic endpoint element in the connectivity graph [ network interface , reserved ip, external cidrs]

type Node interface {
	VPCResourceIntf
	Cidr() string
	IsInternal() bool
	IsPublicInternet() bool
	VPC() VPCResourceIntf // the VPC to which this node belongs to
}

// NodeSet is an element that may capture several nodes [vpc ,subnet, vsi, vpe]
type NodeSet interface {
	VPCResourceIntf
	Nodes() []Node
	Connectivity() *ConnectivityResult
	AddressRange() *common.IPBlock
	VPC() VPCResourceIntf // the VPC to which this node belongs to
}

// FilterTrafficResource capture allowed traffic between 2 endpoints
type FilterTrafficResource interface {
	VPCResourceIntf
	// get the connectivity result when the filterTraffic resource is applied to the given NodeSet element
	AllowedConnectivity(src, dst Node, isIngress bool) (*common.ConnectionSet, error)
	ReferencedIPblocks() []*common.IPBlock
	ConnectivityMap() (map[string]*IPbasedConnectivityResult, error)
	GetConnectivityOutputPerEachElemSeparately() string
}

// routing resource enables connectivity from src to destination via that resource
// fip, pgw, tgw
type RoutingResource interface {
	VPCResourceIntf
	Src() []Node
	Destinations() []Node
	AllowedConnectivity(src, dst Node) *common.ConnectionSet
	ConnectivityMap() map[string]ConfigBasedConnectivityResults
	AppliedFiltersKinds() map[string]bool
}
