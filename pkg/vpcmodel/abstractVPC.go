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
	VPC() VPCResourceIntf // the VPC to which this resource belongs to

	DrawioResourceIntf
}

// VPCResource implements part of the VPCResourceIntf
// every concrete resource type should contain VPCResource and also implement the DrawioResourceIntf
type VPCResource struct {
	ResourceName string
	ResourceUID  string
	ResourceType string
	Zone         string
	// the VPC to which this resource belongs to
	VPCRef VPCResourceIntf `json:"-"`
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

func (n *VPCResource) VPC() VPCResourceIntf {
	return n.VPCRef
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
}

// NodeSet is an element that may capture several nodes [vpc ,subnet, vsi, vpe]
type NodeSet interface {
	VPCResourceIntf
	Nodes() []Node
	Connectivity() *ConnectivityResult
	AddressRange() *common.IPBlock
}

// RulesInFilter for a given layer (SGLayer/NACLLayer) contains specific rules in a specific SG/NACL filter
type RulesInFilter struct {
	// todo: is the assumption that the set of rules will always be kept in a list a valid one?
	Filter int   // sg/nacl index in sgList/naclList in the relevant layer SGLayer/NACLLayer/..
	Rules  []int // list of indexes of rules in the sg/nacl
}

// FilterTrafficResource capture allowed traffic between 2 endpoints
type FilterTrafficResource interface {
	VPCResourceIntf
	// AllowedConnectivity get the connectivity from src Node to dst Node considering this filterTraffic resource
	AllowedConnectivity(src, dst Node, isIngress bool) (*common.ConnectionSet, error)
	// RulesInConnectivity get the list of rules of a given filter that contributes to the connection between src and dst
	// todo: currently implemented only to sg; likely src and dst will be VPCResourceIntf instead of Node
	RulesInConnectivity(src, dst Node, isIngress bool) ([]RulesInFilter, error)
	// IsDefault returns true iff all sgs/nacls/.. are the default ones
	IsDefault() bool
	StringRulesOfFilter(listRulesInFilter []RulesInFilter) string
	ReferencedIPblocks() []*common.IPBlock
	ConnectivityMap() (map[string]*IPbasedConnectivityResult, error)
	GetConnectivityOutputPerEachElemSeparately() string
}

// RoutingResource routing resource enables connectivity from src to destination via that resource
// fip, pgw, tgw
type RoutingResource interface {
	VPCResourceIntf
	Src() []Node
	Destinations() []Node
	AllowedConnectivity(src, dst Node) *common.ConnectionSet
	ConnectivityMap() map[string]ConfigBasedConnectivityResults
	AppliedFiltersKinds() map[string]bool
}
