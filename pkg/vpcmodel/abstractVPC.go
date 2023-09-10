package vpcmodel

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
)

type DrawioResourceIntf interface {
	DrawioTreeNode(gen DrawioGeneratorInt) drawio.TreeNodeInterface
}
// VPCResourceIntf captures common properties for VPC resources
type VPCResourceIntf interface {
	DrawioResourceIntf
	UID() string
	Name() string
	ZoneName() string
	Kind() string
	Details() []string
	DetailsMap() []map[string]string
}

// VPCResource implements VPCResourceIntf
type VPCResource struct {
	ResourceName string
	ResourceUID  string
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

// NodeSet is an element that may capture several nodes [vpc ,subnet, vsi, (service network?)]
type NodeSet interface {
	VPCResourceIntf
	Nodes() []Node
	Connectivity() *ConnectivityResult
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
// fip, pgw, vpe
type RoutingResource interface {
	VPCResourceIntf
	Src() []Node
	Destinations() []Node
	AllowedConnectivity(src, dst Node) *common.ConnectionSet
	ConnectivityMap() map[string]ConfigBasedConnectivityResults
	AppliedFiltersKinds() map[string]bool
}
