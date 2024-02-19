package vpcmodel

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

const (
	leftParentheses  = " ("
	rightParentheses = ")"
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

func (n *VPCResource) NameAndUID() string {
	return n.Name() + leftParentheses + n.UID() + rightParentheses
}

// todo: define enum for filters
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

// RulesType Type of rules in a given filter (e.g. specific NACL table) relevant to
// path between src to destination
type RulesType int

const (
	NoRules       = iota // there are no relevant rules in this filter
	OnlyAllow            // there are only relevant allow rules in this filter
	OnlyDeny             // there are only relevant deny rules in this filter
	BothAllowDeny        // there are relevant allow and deny rules in this filter
	OnlyDummyRule        // This is used to mark a nacl table when src, dst are in the same subnet
)

// RulesInFilter for a given layer (SGLayer/NACLLayer) contains specific rules in a specific SG/NACL filter
type RulesInFilter struct {
	// todo: is the assumption that the set of rules will always be kept in a list a valid one?
	Filter          int   // sg/nacl index in sgList/naclList in the relevant layer SGLayer/NACLLayer/..
	Rules           []int // list of indexes of rules in the sg/nacl
	RulesFilterType RulesType
}

// FilterTrafficResource capture allowed traffic between 2 endpoints
type FilterTrafficResource interface {
	VPCResourceIntf
	// AllowedConnectivity computes the connectivity from src Node to dst Node considering this filterTraffic resource
	AllowedConnectivity(src, dst Node, isIngress bool) (*common.ConnectionSet, error)
	// RulesInConnectivity computes the list of rules of a given filter that contributes to the connection between src and dst
	// if conn is also given the above is per connection
	RulesInConnectivity(src, dst Node, conn *common.ConnectionSet, isIngress bool) ([]RulesInFilter, []RulesInFilter, error)
	// StringDetailsRulesOfFilter gets, for a specific filter (sg/nacl), a struct with relevant rules in it,
	// and prints the effect of each filter (e.g. security group sg1-ky allows connection (with allow rules))
	// and the detailed list of relevant rules
	StringDetailsRulesOfFilter(listRulesInFilter []RulesInFilter) string
	// StringFilterEffect gets the same input as StringDetailsRulesOfFilter, and prints of each filter its effect
	// (namely, it prints only the prefix printed by StringDetailsRulesOfFilter)
	StringFilterEffect(listRulesInFilter []RulesInFilter) string
	ReferencedIPblocks() []*common.IPBlock
	ConnectivityMap() (map[string]*IPbasedConnectivityResult, error)
	GetConnectivityOutputPerEachElemSeparately() string
}

// RoutingResource routing resource enables connectivity from src to destination via that resource
// fip, pgw, tgw
type RoutingResource interface {
	VPCResourceIntf
	Sources() []Node
	Destinations() []Node
	AllowedConnectivity(src, dst VPCResourceIntf) (*common.ConnectionSet, error)
	AppliedFiltersKinds() map[string]bool
}
