/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/models/pkg/spec"
)

const (
	leftParentheses  = " ("
	rightParentheses = ")"
)

// VPCResourceIntf captures common properties for VPC resources
type VPCResourceIntf interface {
	UID() string
	Name() string
	// ExtendedName returns a resource name that includes its VPC as prefix when necessary.
	// for example, a subnet with name "s1" within VPC "v1" will have extended name: "v1/s1"
	// note this method is relevant only for Node and Subnet objects.
	// note it adds the prefix only for input config that has multiple VPCs context.
	ExtendedName(*VPCConfig) string
	// ExtendedPrefix returns the prefix to be added for ExtendedName, given the input config
	ExtendedPrefix(config *VPCConfig) string
	ZoneName() string
	Kind() string
	VPC() VPCResourceIntf // the VPC to which this resource belongs to
	RegionName() string

	FormattableResource
}

// VPCResource implements part of the VPCResourceIntf
// every concrete resource type should contain VPCResource and also implement the FormattableResource
type VPCResource struct {
	ResourceName string
	ResourceUID  string
	ResourceType string
	Zone         string
	Region       string
	// the VPC to which this resource belongs to
	VPCRef VPCResourceIntf `json:"-"`
}

func (n *VPCResource) ExtendedPrefix(c *VPCConfig) string {
	if c.IsMultipleVPCsConfig {
		return n.VPC().Name() + Deliminator
	}
	return ""
}

func (n *VPCResource) Name() string {
	return n.ResourceName
}

func (n *VPCResource) SynthesisResourceName() string {
	return n.VPC().Name() + Deliminator + n.ResourceName
}

func (n *VPCResource) SynthesisKind() spec.ResourceType {
	return ""
}

func (n *VPCResource) ExtendedName(c *VPCConfig) string {
	return n.ExtendedPrefix(c) + n.Name()
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

func (n *VPCResource) RegionName() string {
	return n.Region
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

// Node is the basic endpoint element in the connectivity graph [ network interface , reserved ip, iks node, external cidrs]
type Node interface {
	VPCResourceIntf
	// CidrOrAddress returns the string of the Node's IP-address (for internal node) or CIDR (for external node)
	CidrOrAddress() string
	// IPBlock returns the IPBlock object of the IP addresses associated with this node
	IPBlock() *ipblock.IPBlock
	// IsInternal returns true if the node is internal, within a VPC
	IsInternal() bool
	// IsPublicInternet returns true if the node is external,
	// currently nodes which are external but not public Internet are ignored
	IsPublicInternet() bool
	// AbstractedToNodeSet returns the abstracted nodeSet that contains this node (if any)
	// e.g. the Nodes of Load Balancer private IPs are abstracted by the Load Balancer
	AbstractedToNodeSet() NodeSet
	// RepresentedByAddress - can the node be identified from input address in query
	RepresentedByAddress() bool
}

// InternalNodeIntf captures common properties for internal nodes: single IP address
// Implemented by NetworkInterface, IKSNode, ReservedIP (embedding InternalNode)
type InternalNodeIntf interface {
	// Address returns the node's address
	// an InternalNodeIntf has an exact one IP Address
	Address() string
	// IPBlock returns the IPBlock object representing the node's IP Address
	IPBlock() *ipblock.IPBlock
	// Subnet returns the subnet of the internal node
	Subnet() Subnet
	// AppliedFiltersKinds returns relevant filters for connectivity between internal nodes
	//  specifically, nacl is non-relevant if me and otherNode are in the same subnet
	AppliedFiltersKinds(otherNode InternalNodeIntf) map[string]bool
}

// InternalNode implements interface InternalNodeIntf
type InternalNode struct {
	// AddressStr is an IPv4 string, as the node's IP Address
	AddressStr string
	// IPBlockObj is an IPBlock object of the node's address (created from AddressStr).
	// This field is skipped in the JSON output (nodes connectivity output in JSON format),
	// since it is sufficient to have the AddressStr, and no need to represent IPBlockObj as another
	// attribute in the JSON output.
	IPBlockObj *ipblock.IPBlock `json:"-"`
	// SubnetResource is the subnet on which this node resides in
	SubnetResource Subnet `json:"-"`
}

func (n *InternalNode) Address() string {
	return n.AddressStr
}

func (n *InternalNode) IPBlock() *ipblock.IPBlock {
	return n.IPBlockObj
}

func (n *InternalNode) Subnet() Subnet {
	return n.SubnetResource
}

// AppliedFiltersKinds returns relevant filters between two internal nodes
func (n *InternalNode) AppliedFiltersKinds(otherNode InternalNodeIntf) map[string]bool {
	res := map[string]bool{SecurityGroupLayer: true}
	if n.Subnet().UID() != otherNode.Subnet().UID() {
		res[NaclLayer] = true
	}
	return res
}

// SetIPBlockFromAddress sets the node's IPBlockObj field from its AddressStr field.
// Assumes its AddressStr field is assigned with valid IPv4 string value.
func (n *InternalNode) SetIPBlockFromAddress() (err error) {
	n.IPBlockObj, err = ipblock.FromIPAddress(n.AddressStr)
	return err
}

func (n *InternalNode) CidrOrAddress() string {
	return n.AddressStr
}

func (n *InternalNode) IsInternal() bool {
	return true
}

func (n *InternalNode) IsPublicInternet() bool {
	return false
}

// only lb are abstracted, so only pip has AbstractedToNodeSet
func (n *InternalNode) AbstractedToNodeSet() NodeSet {
	return nil
}

func (n *InternalNode) RepresentedByAddress() bool {
	return true
}

// NodeSet is an element that may capture several nodes [vsi, vpe, vpc ,subnet]
type NodeSet interface {
	VPCResourceIntf
	Nodes() []Node
	AddressRange() *ipblock.IPBlock
}

type VPC interface {
	NodeSet
	AddressPrefixes() *ipblock.IPBlock
}

type Subnet interface {
	NodeSet
	CIDR() string
	IsPrivate() bool
	GetPrivateSubnetRule(src, dst Node) PrivateSubnetRule
}

// LoadBalancer is elaboration of a NodeSet - the nodes are the private IPs of the load balancer
// todo: elaborate more - get list of servers, expandability,...
type LoadBalancer interface {
	NodeSet
	GetLoadBalancerRule(src, dst Node) LoadBalancerRule
	SetAbstractionInfo(*AbstractionInfo)
	AbstractionInfo() *AbstractionInfo
}

type miscConnectivityRule interface {
	Deny(bool) bool
	IsIngress() bool
	String(detailed bool) string
}

// LoadBalancerRule represent the influence of the load balancer on a connectivity
type LoadBalancerRule miscConnectivityRule

// PrivateSubnetRule represent the influence of the private/public subnets on a connectivity
// relevant only for providers that allows the user to set subnets as privates (currently aws)
type PrivateSubnetRule miscConnectivityRule

// RulesType Type of rules in a given filter (e.g. specific NACL table) relevant to
// path between src to destination
type RulesType int

const (
	NoRules       = iota // there are no relevant rules in this filter
	OnlyAllow            // there are only relevant allow rules in this filter
	OnlyDeny             // there are only relevant deny rules in this filter
	BothAllowDeny        // there are relevant allow and deny rules in this filter
)

// TableEffect Type: given a queried src, dst, and potentially conn the table may:
// deny the entire connection; allow the entire connection; partly allow the connection
// if the query does not include connection then the effect is restricted to allow (any connection from src to dst)
// and deny (all connections from src to dst)
type TableEffect int

const (
	Allow = iota
	PartlyAllow
	Deny
)

// RulesInTable for a given layer (SGLayer/NACLLayer) or transit gateway contains
// index of the SG/NACL/transit gateway filter and the indexes of the rules within it
// this struct is also used for intermediate computation of only allow or only deny rules; TableHasEffect is always
// w.r.t. the entire table
// todo: once transformation is completed - can be un-exported and moved to rulesDetailesProvided?
type RulesInTable struct {
	// todo: is the assumption that the set of rules will always be kept in a list a valid one?
	TableIndex     int   // sg/nacl/transit connection index in sgList/naclList/tgwConnList
	Rules          []int // list of indexes of rules in the sg/nacl/transit connection
	RulesOfType    RulesType
	TableHasEffect TableEffect // effect of the table w.r.t. queried src, dst and query
}

// RuleOfFilter a single rule in filter given the layer (SGLayer/NACLLayer)
type RuleOfFilter struct {
	Filter    Filter
	RuleIndex int              `json:"rule_index"`
	IsIngress bool             `json:"inbound_rule"`
	SrcCidr   *ipblock.IPBlock `json:"src_cidr"`
	DstCidr   *ipblock.IPBlock `json:"dst_cidr"`
	Conn      *connection.Set  `json:"rule_connection"`
	RuleDesc  string           `json:"rule_description"`
}

type Filter struct {
	LayerName   string `json:"layer"`
	FilterName  string `json:"table"`
	FilterIndex int    `json:"-"`
}

func NewRuleOfFilter(layerName, filterName, desc string, filterIndex, ruleIndex int,
	isIngress bool, srcBlock, dstBlock *ipblock.IPBlock, conn *connection.Set) *RuleOfFilter {
	table := Filter{LayerName: layerName, FilterIndex: filterIndex, FilterName: filterName}
	srcBlock = getCidrAllIfNil(srcBlock)
	dstBlock = getCidrAllIfNil(dstBlock)
	return &RuleOfFilter{IsIngress: isIngress, Filter: table, RuleIndex: ruleIndex, RuleDesc: desc,
		SrcCidr: srcBlock, DstCidr: dstBlock, Conn: conn}
}

func getCidrAllIfNil(block *ipblock.IPBlock) *ipblock.IPBlock {
	if block == nil {
		return ipblock.GetCidrAll()
	}
	return block
}

// FiltersAttachedResources is a map from each filter to the resources attached to it; e.g. from NACL to subnets
type FiltersAttachedResources map[Filter][]VPCResourceIntf

// FilterTrafficResource capture allowed traffic between 2 endpoints
type FilterTrafficResource interface {
	VPCResourceIntf
	// AllowedConnectivity computes the connectivity from src Node to dst Node considering this filterTraffic resource
	AllowedConnectivity(src, dst Node, isIngress bool) (*connection.Set, error)
	// RulesInConnectivity computes the list of rules of a given filter that contributes to the connection between src and dst
	// if conn is also given the above is per connection
	RulesInConnectivity(src, dst Node, conn *connection.Set, isIngress bool) ([]RulesInTable, []RulesInTable, error)
	// GetRules gets a list of all rules with description
	GetRules() ([]RuleOfFilter, error)
	// GetFiltersAttachedResources gets a map from each filter to the resources attached to it; e.g. from NACL to subnets
	GetFiltersAttachedResources() FiltersAttachedResources
	ReferencedIPblocks() []*ipblock.IPBlock
	ConnectivityMap() (map[string]*IPbasedConnectivityResult, error)
	GetConnectivityOutputPerEachElemSeparately() string
}

// RoutingResource routing resource enables connectivity from src to destination via that resource
// fip, pgw, tgw
type RoutingResource interface {
	VPCResourceIntf
	Sources() []Node
	SourcesSubnets() []Subnet
	Destinations() []Node
	SetExternalDestinations([]Node)
	AllowedConnectivity(src, dst VPCResourceIntf) (*connection.Set, error)
	RulesInConnectivity(src, dst Node) []RulesInTable
	ExternalIP() string // ExternalIP of fip, empty string for other resources
	// RouterDefined is this router defined for src and dst? while fip, pgw are defined for src, dst iff they enable traffic
	// tgw may be defined for src, dst and deny traffic
	RouterDefined(src, dst Node) bool
	// StringOfRouterRules returns a string with the prefix that determines the tgw related routing
	// between src and dst; if non tgw relevant to <src, dst> returns an empty string
	// Non-relevant for fip and pgw, returns always an empty string
	StringOfRouterRules(listRulesInFilter []RulesInTable, verbose bool) (string, error)
	// IsMultipleVPCs() - is the router for connections between VPCs
	IsMultipleVPCs() bool
}
