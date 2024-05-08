/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

const newline = "\n"

func getNodeName(name, addr string) string {
	return fmt.Sprintf("%s[%s]", name, addr)
}

type Region struct {
	name string
}

type Zone struct {
	name string
	vpc  *VPC
}

func (z *Zone) VPC() *VPC {
	return z.vpc
}

func zoneFromVPCResource(r vpcmodel.VPCResourceIntf) (*Zone, error) {
	if vpc, ok := r.VPC().(*VPC); ok {
		return vpc.getZoneByName(r.ZoneName())
	}
	return nil, errors.New("error getting VPC from resource object")
}

// ReservedIP implements vpcmodel.Node interface
type ReservedIP struct {
	vpcmodel.VPCResource
	vpcmodel.InternalNode
	vpe string
}

func (r *ReservedIP) Name() string {
	return getNodeName(r.vpe, r.Address())
}

func (r *ReservedIP) ExtendedName(c *vpcmodel.VPCConfig) string {
	return r.ExtendedPrefix(c) + r.Name()
}

// PrivateIP implements vpcmodel.Node interface
type PrivateIP struct {
	vpcmodel.VPCResource
	vpcmodel.InternalNode
	loadBalancer string
}

func (pip *PrivateIP) Name() string {
	return getNodeName(pip.loadBalancer, pip.Address())
}

func (pip *PrivateIP) ExtendedName(c *vpcmodel.VPCConfig) string {
	return pip.ExtendedPrefix(c) + pip.Name()
}

// NetworkInterface implements vpcmodel.Node interface
type NetworkInterface struct {
	vpcmodel.VPCResource
	vpcmodel.InternalNode
	vsi string
}

func (ni *NetworkInterface) VsiName() string {
	return ni.vsi
}

func (ni *NetworkInterface) Name() string {
	return getNodeName(ni.vsi, ni.Address())
}

func (ni *NetworkInterface) ExtendedName(c *vpcmodel.VPCConfig) string {
	return ni.ExtendedPrefix(c) + ni.Name()
}

// IKSNode implements vpcmodel.Node interface
type IKSNode struct {
	vpcmodel.VPCResource
	vpcmodel.InternalNode
}

func (n *IKSNode) VsiName() string {
	return ""
}

func (n *IKSNode) Name() string {
	return getNodeName(n.ResourceName, n.Address())
}

func (n *IKSNode) ExtendedName(c *vpcmodel.VPCConfig) string {
	return n.ExtendedPrefix(c) + n.Name()
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// nodesets elements - implement vpcmodel.NodeSet interface

// VPC implements vpcmodel.VPC
type VPC struct {
	vpcmodel.VPCResource
	nodes []vpcmodel.Node
	zones map[string]*Zone
	// internalAddressRange is the union of all the vpc's subnets' CIDRs
	internalAddressRange   *ipblock.IPBlock
	subnetsList            []*Subnet
	addressPrefixes        []string
	addressPrefixesIPBlock *ipblock.IPBlock
	region                 *Region
}

func (v *VPC) Region() *Region {
	return v.region
}

func (v *VPC) AddressPrefixes() []string {
	return v.addressPrefixes
}

func (v *VPC) getZoneByName(name string) (*Zone, error) {
	if z, ok := v.zones[name]; ok {
		return z, nil
	}
	return nil, fmt.Errorf("zone %s not found in vpc %s", name, v.ResourceName)
}

func (v *VPC) Nodes() []vpcmodel.Node {
	return v.nodes
}

func (v *VPC) AddressRange() *ipblock.IPBlock {
	return v.internalAddressRange
}

func (v *VPC) subnets() []*Subnet {
	return v.subnetsList
}

// Subnet implements vpcmodel.Subnet interface
type Subnet struct {
	vpcmodel.VPCResource
	nodes   []vpcmodel.Node
	cidr    string
	ipblock *ipblock.IPBlock
}

func (s *Subnet) CIDR() string {
	return s.cidr
}

func (s *Subnet) Zone() (*Zone, error) {
	return zoneFromVPCResource(s)
}

func (s *Subnet) Nodes() []vpcmodel.Node {
	return s.nodes
}

func (s *Subnet) AddressRange() *ipblock.IPBlock {
	return s.ipblock
}

type Vsi struct {
	vpcmodel.VPCResource
	nodes []vpcmodel.Node
}

func (v *Vsi) Zone() (*Zone, error) {
	return zoneFromVPCResource(v)
}

func (v *Vsi) Nodes() []vpcmodel.Node {
	return v.nodes
}

func (v *Vsi) AddressRange() *ipblock.IPBlock {
	return nodesAddressRange(v.nodes)
}

func nodesAddressRange(nodes []vpcmodel.Node) *ipblock.IPBlock {
	var res *ipblock.IPBlock
	for _, n := range nodes {
		if res == nil {
			res = n.IPBlock()
		} else {
			res = res.Union(n.IPBlock())
		}
	}
	return res
}

// vpe can be in multiple zones - depending on the zones of its network interfaces..
type Vpe struct {
	vpcmodel.VPCResource
	nodes []vpcmodel.Node
}

func (v *Vpe) Nodes() []vpcmodel.Node {
	return v.nodes
}

func (v *Vpe) AddressRange() *ipblock.IPBlock {
	return nodesAddressRange(v.nodes)
}

// vpe is per vpc and not per zone...
func (v *Vpe) Zone() (*Zone, error) {
	return nil, nil
}

// //////////////////////////////////////////
// Load Balancer
// the nodes are the private IPs
// for now the listeners holds the pools that holds the backend servers
// todo - implement more...
type LoadBalancerPool []vpcmodel.Node
type LoadBalancerListener []LoadBalancerPool

type LoadBalancer struct {
	vpcmodel.VPCResource
	nodes     []vpcmodel.Node
	listeners []LoadBalancerListener
}

func (lb *LoadBalancer) Nodes() []vpcmodel.Node {
	return lb.nodes
}
func (lb *LoadBalancer) AddressRange() *ipblock.IPBlock {
	return nodesAddressRange(lb.nodes)
}

// we do not need this func, for now it is here since the linter warn that lb.listeners are not in use
// todo - remove:
func (lb *LoadBalancer) NListeners() int {
	return len(lb.listeners)
}

// lb is per vpc and not per zone...
func (lb *LoadBalancer) Zone() (*Zone, error) {
	return nil, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// FilterTraffic elements

type NaclLayer struct {
	vpcmodel.VPCResource
	naclList []*NACL
}

// per-layer connectivity analysis
// compute allowed connectivity based on the NACL resources for all relevant endpoints (subnets)
func (nl *NaclLayer) ConnectivityMap() (map[string]*vpcmodel.IPbasedConnectivityResult, error) {
	res := map[string]*vpcmodel.IPbasedConnectivityResult{} // map from subnet cidr to its connectivity result
	for _, nacl := range nl.naclList {
		for subnetCidr, subnet := range nacl.subnets {
			_, resConnectivity := nacl.analyzer.GeneralConnectivityPerSubnet(subnet)
			// TODO: currently supporting only handling full-range of subnet connectivity-map, not partial range of subnet
			if len(resConnectivity) != 1 {
				return nil, errors.New("unsupported connectivity map with partial subnet ranges per connectivity result")
			}
			subnetKey := subnet.ipblock.ToIPRanges()
			if _, ok := resConnectivity[subnetKey]; !ok {
				return nil, errors.New("unexpected subnet connectivity result - key is different from subnet cidr")
			}
			res[subnetCidr] = resConnectivity[subnetKey]
		}
	}
	return res, nil
}

func (nl *NaclLayer) GetConnectivityOutputPerEachElemSeparately() string {
	res := []string{}
	// iterate over all subnets, collect all outputs per subnet connectivity
	for _, nacl := range nl.naclList {
		for _, subnet := range nacl.subnets {
			res = append(res, nacl.GeneralConnectivityPerSubnet(subnet))
		}
	}
	sort.Strings(res)
	return strings.Join(res, "\n")
}

func (nl *NaclLayer) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) (*connection.Set, error) {
	res := connection.None()
	for _, nacl := range nl.naclList {
		naclConn, err := nacl.AllowedConnectivity(src, dst, isIngress)
		if err != nil {
			return nil, err
		}
		res = res.Union(naclConn)
	}
	return res, nil
}

// RulesInConnectivity list of NACL rules contributing to the connectivity
func (nl *NaclLayer) RulesInConnectivity(src, dst vpcmodel.Node,
	conn *connection.Set, isIngress bool) (allowRes []vpcmodel.RulesInTable,
	denyRes []vpcmodel.RulesInTable, err error) {
	for index, nacl := range nl.naclList {
		tableRelevant, allowRules, denyRules, err1 := nacl.rulesFilterInConnectivity(src, dst, conn, isIngress)
		if err1 != nil {
			return nil, nil, err1
		}
		if !tableRelevant {
			continue
		}
		appendToRulesInFilter(&allowRes, &allowRules, index, true)
		appendToRulesInFilter(&denyRes, &denyRules, index, false)
	}
	return allowRes, denyRes, nil
}

func (nl *NaclLayer) Name() string {
	return ""
}

func appendToRulesInFilter(resRulesInFilter *[]vpcmodel.RulesInTable, rules *[]int, filterIndex int, isAllow bool) {
	var rType vpcmodel.RulesType
	switch {
	case len(*rules) == 0:
		rType = vpcmodel.NoRules
	case isAllow:
		rType = vpcmodel.OnlyAllow
	default: // more than 0 deny rules
		rType = vpcmodel.OnlyDeny
	}
	rulesInNacl := vpcmodel.RulesInTable{
		Table:           filterIndex,
		Rules:           *rules,
		RulesFilterType: rType,
	}
	*resRulesInFilter = append(*resRulesInFilter, rulesInNacl)
}

func (nl *NaclLayer) StringDetailsOfRules(listRulesInFilter []vpcmodel.RulesInTable) string {
	strListRulesInFilter := ""
	for _, rulesInFilter := range listRulesInFilter {
		nacl := nl.naclList[rulesInFilter.Table]
		header := getHeaderRulesType(vpcmodel.FilterKindName(nl.Kind())+" "+nacl.Name(), rulesInFilter.RulesFilterType) +
			nacl.analyzer.StringRules(rulesInFilter.Rules)
		strListRulesInFilter += header
	}
	return strListRulesInFilter
}

func (nl *NaclLayer) ListFilterWithAction(listRulesInFilter []vpcmodel.RulesInTable) (filters map[string]bool) {
	filters = map[string]bool{}
	for _, rulesInFilter := range listRulesInFilter {
		nacl := nl.naclList[rulesInFilter.Table]
		name := nacl.Name()
		filters[name] = getFilterAction(rulesInFilter.RulesFilterType)
	}
	return filters
}

func (nl *NaclLayer) ReferencedIPblocks() []*ipblock.IPBlock {
	res := []*ipblock.IPBlock{}
	for _, n := range nl.naclList {
		res = append(res, n.analyzer.referencedIPblocks...)
	}
	return res
}

func getHeaderRulesType(filter string, rType vpcmodel.RulesType) string {
	switch rType {
	case vpcmodel.NoRules:
		return filter + " blocks connection since there are no relevant allow rules\n"
	case vpcmodel.OnlyDeny:
		return filter + " blocks connection with the following deny rules:\n"
	case vpcmodel.BothAllowDeny:
		return filter + " allows connection with the following allow and deny rules\n"
	case vpcmodel.OnlyAllow:
		return filter + " allows connection with the following allow rules\n"
	default:
		return ""
	}
}

// returns true of the filter allows traffic, false if it blocks traffic
func getFilterAction(rType vpcmodel.RulesType) bool {
	switch rType {
	case vpcmodel.BothAllowDeny, vpcmodel.OnlyAllow:
		return true
	default:
		return false
	}
}

type NACL struct {
	vpcmodel.VPCResource
	subnets  map[string]*Subnet // map of subnets (pair of cidr strings and subnet obj) for which this nacl is applied to
	analyzer *NACLAnalyzer
}

func (n *NACL) GeneralConnectivityPerSubnet(subnet *Subnet) string {
	res, _ := n.analyzer.GeneralConnectivityPerSubnet(subnet)
	return res
}

func subnetFromNode(node vpcmodel.Node) (subnet *Subnet, err error) {
	switch concreteNode := node.(type) {
	case vpcmodel.InternalNodeIntf:
		return concreteNode.Subnet().(*Subnet), nil
	default:
		return nil, fmt.Errorf("cannot get subnet for node: %+v", node)
	}
}

type naclConnectivityInput struct {
	targetNode           vpcmodel.Node
	nodeInSubnet         vpcmodel.Node
	subnet               *Subnet
	subnetAffectedByNACL bool
	targetWithinSubnet   bool
}

func (n *NACL) initConnectivityComputation(src, dst vpcmodel.Node,
	isIngress bool) (
	connectivityInput *naclConnectivityInput,
	err error) {
	connectivityInput = &naclConnectivityInput{}
	if isIngress {
		connectivityInput.targetNode, connectivityInput.nodeInSubnet = src, dst
	} else {
		connectivityInput.targetNode, connectivityInput.nodeInSubnet = dst, src
	}
	connectivityInput.subnet, err = subnetFromNode(connectivityInput.nodeInSubnet)
	if err != nil {
		return nil, err
	}
	if _, ok := n.subnets[connectivityInput.subnet.cidr]; ok {
		connectivityInput.subnetAffectedByNACL = true
	}
	// checking if targetNode is internal, to save a call to ContainedIn for external nodes
	if connectivityInput.targetNode.IsInternal() &&
		connectivityInput.targetNode.IPBlock().ContainedIn(connectivityInput.subnet.ipblock) {
		connectivityInput.targetWithinSubnet = true
	}

	return connectivityInput, nil
}

func (n *NACL) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) (*connection.Set, error) {
	connectivityInput, err := n.initConnectivityComputation(src, dst, isIngress)
	if err != nil {
		return nil, err
	}
	// check if the subnet of the given node is affected by this nacl
	if !connectivityInput.subnetAffectedByNACL {
		return connection.None(), nil // not affected by current nacl
	}
	// TODO: differentiate between "has no effect" vs "affects with allow-all / allow-none "
	if connectivityInput.targetWithinSubnet {
		return connection.All(), nil // nacl has no control on traffic between two instances in its subnet
	}
	return n.analyzer.AllowedConnectivity(connectivityInput.subnet, connectivityInput.nodeInSubnet,
		connectivityInput.targetNode, isIngress)
}

// TODO: rulesFilterInConnectivity has some duplicated code with AllowedConnectivity
func (n *NACL) rulesFilterInConnectivity(src, dst vpcmodel.Node, conn *connection.Set,
	isIngress bool) (tableRelevant bool, allow, deny []int, err error) {
	connectivityInput, err1 := n.initConnectivityComputation(src, dst, isIngress)
	if err1 != nil {
		return false, nil, nil, err1
	}
	// check if the subnet of the given node is affected by this nacl
	if !connectivityInput.subnetAffectedByNACL {
		return false, nil, nil, nil // not affected by current nacl
	}
	// nacl has no control on traffic between two instances in its subnet;
	if connectivityInput.targetWithinSubnet {
		return false, []int{}, nil, nil
	}
	var err2 error
	allow, deny, err2 = n.analyzer.rulesFilterInConnectivity(connectivityInput.subnet, connectivityInput.nodeInSubnet,
		connectivityInput.targetNode, conn, isIngress)
	return true, allow, deny, err2
}

// SecurityGroupLayer captures all SG in the vpc config, analyzes connectivity considering all SG resources
type SecurityGroupLayer struct {
	vpcmodel.VPCResource
	sgList []*SecurityGroup
}

func (sgl *SecurityGroupLayer) Name() string {
	return ""
}

func (sgl *SecurityGroupLayer) ConnectivityMap() (map[string]*vpcmodel.IPbasedConnectivityResult, error) {
	return nil, nil
}

func (sgl *SecurityGroupLayer) GetConnectivityOutputPerEachElemSeparately() string {
	return ""
}

// AllowedConnectivity
// TODO: fix: is it possible that no sg applies  to the input peer? if so, should not return "no conns" when none applies
func (sgl *SecurityGroupLayer) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) (*connection.Set, error) {
	res := connection.None()
	for _, sg := range sgl.sgList {
		sgConn := sg.AllowedConnectivity(src, dst, isIngress)
		res = res.Union(sgConn)
	}
	return res, nil
}

// RulesInConnectivity return allow rules between src and dst,
// or between src and dst of connection conn if conn specified
// denyRules not relevant here - returns nil
func (sgl *SecurityGroupLayer) RulesInConnectivity(src, dst vpcmodel.Node,
	conn *connection.Set, isIngress bool) (allowRes []vpcmodel.RulesInTable,
	denyRes []vpcmodel.RulesInTable, err error) {
	for index, sg := range sgl.sgList {
		tableRelevant, sgRules, err1 := sg.rulesFilterInConnectivity(src, dst, conn, isIngress)
		if err1 != nil {
			return nil, nil, err1
		}
		if tableRelevant {
			var rType vpcmodel.RulesType = vpcmodel.OnlyAllow
			if len(sgRules) == 0 {
				rType = vpcmodel.NoRules
			}
			rulesInSg := vpcmodel.RulesInTable{
				Table:           index,
				Rules:           sgRules,
				RulesFilterType: rType,
			}
			allowRes = append(allowRes, rulesInSg)
		}
	}
	return allowRes, nil, nil
}

func (sgl *SecurityGroupLayer) StringDetailsOfRules(listRulesInFilter []vpcmodel.RulesInTable) string {
	listRulesInFilterSlice := make([]string, len(listRulesInFilter))
	for i, rulesInFilter := range listRulesInFilter {
		sg := sgl.sgList[rulesInFilter.Table]
		listRulesInFilterSlice[i] = getHeaderRulesType(vpcmodel.FilterKindName(sgl.Kind())+" "+sg.Name(), rulesInFilter.RulesFilterType) +
			sg.analyzer.StringRules(rulesInFilter.Rules)
	}
	sort.Strings(listRulesInFilterSlice)
	return strings.Join(listRulesInFilterSlice, "")
}

func (sgl *SecurityGroupLayer) ListFilterWithAction(listRulesInFilter []vpcmodel.RulesInTable) (filters map[string]bool) {
	filters = map[string]bool{}
	for _, rulesInFilter := range listRulesInFilter {
		sg := sgl.sgList[rulesInFilter.Table]
		name := sg.Name()
		filters[name] = getFilterAction(rulesInFilter.RulesFilterType)
	}
	return filters
}

func (sgl *SecurityGroupLayer) ReferencedIPblocks() []*ipblock.IPBlock {
	res := []*ipblock.IPBlock{}
	for _, sg := range sgl.sgList {
		res = append(res, sg.analyzer.referencedIPblocks...)
	}
	return res
}

type SecurityGroup struct {
	vpcmodel.VPCResource
	analyzer *SGAnalyzer
	// map of SG members, key is IP-address: pairs(address[string], object[NetworkInterface/ReservedIP])
	members map[string]vpcmodel.Node
}

func (sg *SecurityGroup) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) *connection.Set {
	memberStrAddress, targetIPBlock := sg.getMemberTargetStrAddress(src, dst, isIngress)
	if _, ok := sg.members[memberStrAddress]; !ok {
		return connection.None() // connectivity not affected by this SG resource - input node is not its member
	}
	return sg.analyzer.AllowedConnectivity(targetIPBlock, isIngress)
}

// rulesFilterInConnectivity list of SG rules contributing to the connectivity
func (sg *SecurityGroup) rulesFilterInConnectivity(src, dst vpcmodel.Node, conn *connection.Set,
	isIngress bool) (tableRelevant bool, rules []int, err error) {
	memberStrAddress, targetIPBlock := sg.getMemberTargetStrAddress(src, dst, isIngress)
	if _, ok := sg.members[memberStrAddress]; !ok {
		return false, nil, nil // connectivity not affected by this SG resource - input node is not its member
	}
	rules, err = sg.analyzer.rulesFilterInConnectivity(targetIPBlock, conn, isIngress)
	return true, rules, err
}

func (sg *SecurityGroup) getMemberTargetStrAddress(src, dst vpcmodel.Node,
	isIngress bool) (memberStrAddress string, targetIPBlock *ipblock.IPBlock) {
	var member, target vpcmodel.Node
	if isIngress {
		member, target = dst, src
	} else {
		member, target = src, dst
	}
	// TODO: member is expected to be internal node (validate?) [could use member.(vpcmodel.InternalNodeIntf).Address()]
	return member.CidrOrAddress(), target.IPBlock()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

// routing resource elements

type FloatingIP struct {
	vpcmodel.VPCResource
	cidr         string // todo: this is actually not cidr but external IP. Rename?
	src          []vpcmodel.Node
	destinations []vpcmodel.Node
}

func (fip *FloatingIP) Sources() []vpcmodel.Node {
	return fip.src
}
func (fip *FloatingIP) Destinations() []vpcmodel.Node {
	return fip.destinations
}

func (fip *FloatingIP) AllowedConnectivity(src, dst vpcmodel.VPCResourceIntf) (*connection.Set, error) {
	if areNodes, src1, dst1 := isNodesPair(src, dst); areNodes {
		if vpcmodel.HasNode(fip.Sources(), src1) && dst1.IsExternal() {
			return connection.All(), nil
		}
		if vpcmodel.HasNode(fip.Sources(), dst1) && src1.IsExternal() {
			return connection.All(), nil
		}
		return connection.None(), nil
	}
	return nil, errors.New("FloatingIP.AllowedConnectivity unexpected src/dst types")
}

func (fip *FloatingIP) RouterDefined(src, dst vpcmodel.Node) bool {
	return (vpcmodel.HasNode(fip.Sources(), src) && dst.IsExternal()) ||
		(vpcmodel.HasNode(fip.Sources(), dst) && src.IsExternal())
}

func (fip *FloatingIP) AppliedFiltersKinds() map[string]bool {
	return map[string]bool{vpcmodel.SecurityGroupLayer: true}
}

func (fip *FloatingIP) ExternalIP() string {
	return fip.cidr
}

func (fip *FloatingIP) StringPrefixDetails(src, dst vpcmodel.Node, verbose bool) (string, error) {
	return "", nil
}

func (fip *FloatingIP) RulesInConnectivity(src, dst vpcmodel.Node) ([]vpcmodel.RulesInTable, error) {
	return nil, nil
}

func (fip *FloatingIP) StringDetailsOfRules(listRulesInFilter []vpcmodel.RulesInTable) string {
	return ""
}

type PublicGateway struct {
	vpcmodel.VPCResource
	cidr         string
	src          []vpcmodel.Node
	destinations []vpcmodel.Node
	srcSubnets   []*Subnet
	subnetCidr   []string
	vpc          *VPC
}

func (pgw *PublicGateway) Zone() (*Zone, error) {
	return pgw.vpc.getZoneByName(pgw.ZoneName())
}

func (pgw *PublicGateway) Sources() []vpcmodel.Node {
	return pgw.src
}
func (pgw *PublicGateway) Destinations() []vpcmodel.Node {
	return pgw.destinations
}
func (pgw *PublicGateway) ExternalIP() string {
	return ""
}

func (pgw *PublicGateway) AllowedConnectivity(src, dst vpcmodel.VPCResourceIntf) (*connection.Set, error) {
	if areNodes, src1, dst1 := isNodesPair(src, dst); areNodes {
		if vpcmodel.HasNode(pgw.Sources(), src1) && dst1.IsExternal() {
			return connection.All(), nil
		}
		return connection.None(), nil
	}
	if src.Kind() == ResourceTypeSubnet {
		srcSubnet := src.(*Subnet)
		if dstNode, ok := dst.(vpcmodel.Node); ok {
			if dstNode.IsExternal() && hasSubnet(pgw.srcSubnets, srcSubnet) {
				return connection.All(), nil
			}
			return connection.None(), nil
		}
	}
	return nil, errors.New("unexpected src/dst input types")
}

func (pgw *PublicGateway) RouterDefined(src, dst vpcmodel.Node) bool {
	return vpcmodel.HasNode(pgw.Sources(), src) && dst.IsExternal()
}

func (pgw *PublicGateway) AppliedFiltersKinds() map[string]bool {
	return map[string]bool{vpcmodel.NaclLayer: true, vpcmodel.SecurityGroupLayer: true}
}

func (pgw *PublicGateway) StringPrefixDetails(src, dst vpcmodel.Node, verbose bool) (string, error) {
	return "", nil
}

func (pgw *PublicGateway) RulesInConnectivity(src, dst vpcmodel.Node) ([]vpcmodel.RulesInTable, error) {
	return nil, nil
}

func (pgw *PublicGateway) StringDetailsOfRules(listRulesInFilter []vpcmodel.RulesInTable) string {
	return ""
}

// todo: remove
// a tgw prefix filter (for explainability)
type tgwPrefixFilter struct {
	tc    *datamodel.TransitConnection // the TransitConnection  where this filter is defined
	index int                          // the index of this prefix filter within the TransitConnection's filters list
	// value -1  refers to the default prefix filter
}

// todo: remove
// IPBlockPrefixFilter  captures for a certain address-prefix, the details of its matching prefix-filter
type IPBlockPrefixFilter struct {
	IPBlock      *ipblock.IPBlock // the IPBlock of the address-prefix
	prefixFilter tgwPrefixFilter  // the matching tgw prefix filter for this address-prefix
}

type TransitGateway struct {
	vpcmodel.VPCResource

	// vpcs are the VPCs connected by a TGW
	vpcs []*VPC

	// list of transit connections of the tgw
	tgwConnList []*datamodel.TransitConnection

	// availableRoutes are the published address prefixes from all connected vpcs that arrive at the TGW's table of available routes,
	// as considered from prefix filters: map from vpc UID to its available routes in the routes table
	availableRoutes map[string][]*ipblock.IPBlock

	// sourceSubnets are the subnets from the connected vpcs that can have connection to destination
	// subnet from another vpc
	sourceSubnets []*Subnet

	// destSubnets are the subnets from the connected vpcs that can de destination for a connection from
	// remote source subnet from another vpc, based on the availableRoutes in the TGW
	destSubnets []*Subnet

	sourceNodes []vpcmodel.Node
	destNodes   []vpcmodel.Node

	region *Region

	// maps each VPC UID to a slice - listing for each of its AP (as IPBlock) details of the matching filter
	// Specifically, these details include the specific transit connection and the index of the matching
	// filter if exists (index "-1" is for default )
	// this struct can be though of as the "explain" parallel of availableRoutes; note that unlike availableRoutes it also lists deny prefixes
	vpcsAPToFiltersOld map[string][]IPBlockPrefixFilter

	// maps each VPC UID to the details of the matching filters
	// these details includes map of each relevant IPBlock to the transit connection (its index in the TgwLayer)
	// and the index of the matching filter in the transit connection if exists (index "-1" is for default )
	// this struct can be though of as the "explain" parallel of availableRoutes; note that unlike availableRoutes it also lists deny prefixes
	vpcsAPToPrefixRules map[string]map[*ipblock.IPBlock]vpcmodel.RulesInTable
}

func (tgw *TransitGateway) addSourceAndDestNodes() {
	for _, subnet := range tgw.sourceSubnets {
		tgw.sourceNodes = append(tgw.sourceNodes, subnet.Nodes()...)
	}
	for _, subnet := range tgw.destSubnets {
		tgw.destNodes = append(tgw.destNodes, subnet.Nodes()...)
	}
}

func (tgw *TransitGateway) Region() *Region {
	return tgw.region
}

func (tgw *TransitGateway) Sources() (res []vpcmodel.Node) {
	return tgw.sourceNodes
}
func (tgw *TransitGateway) Destinations() (res []vpcmodel.Node) {
	return tgw.destNodes
}
func (tgw *TransitGateway) ExternalIP() string {
	return ""
}

func (tgw *TransitGateway) AllowedConnectivity(src, dst vpcmodel.VPCResourceIntf) (*connection.Set, error) {
	if areNodes, src1, dst1 := isNodesPair(src, dst); areNodes {
		if vpcmodel.HasNode(tgw.sourceNodes, src1) && vpcmodel.HasNode(tgw.destNodes, dst1) {
			return connection.All(), nil
		}
		return connection.None(), nil
	}
	if areSubnets, src1, dst1 := isSubnetsPair(src, dst); areSubnets {
		if hasSubnet(tgw.sourceSubnets, src1) && hasSubnet(tgw.destSubnets, dst1) {
			return connection.All(), nil
		}
		return connection.None(), nil
	}

	return nil, errors.New("TransitGateway.AllowedConnectivity() expected src and dst to be two nodes or two subnets")
}

func (tgw *TransitGateway) RouterDefined(src, dst vpcmodel.Node) bool {
	// destination node has a transit gateway connection iff a prefix filter (possibly default) is defined for it
	dstNodeHasTgw := tgw.prefixesOfSrcDst(src, dst) != nil
	return vpcmodel.HasNode(tgw.sourceNodes, src) && dstNodeHasTgw
}

// gets a string description of prefix indexed "index" from TransitGateway tgw
func prefixDefaultStr(tc *datamodel.TransitConnection) (string, error) {
	actionName, err := actionNameStr(tc.PrefixFiltersDefault)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(" default prefix,  action: %s", actionName), nil
}

func (tgw *TransitGateway) tgwPrefixStr(prefix tgwPrefixFilter) (string, error) {
	// Array of prefix route filters for a transit gateway connection. This is order dependent with those first in the
	// array being applied first, and those at the end of the array is applied last, or just before the default.
	resStr := fmt.Sprintf("transit-connection: %s", *prefix.tc.Name)
	if prefix.index == defaultPrefixFilter { // default
		defaultStr, err := prefixDefaultStr(prefix.tc)
		if err != nil {
			return "", err
		}
		return resStr + defaultStr, nil
	}
	if len(prefix.tc.PrefixFilters) < prefix.index+1 {
		return "", fmt.Errorf("np-guard error: prefix index %d does not exists in transit connection %s of transit gateway %s",
			prefix.index, *prefix.tc.Name, tgw.Name())
	}
	prefixFilter := prefix.tc.PrefixFilters[prefix.index]
	actionName, err := actionNameStr(prefixFilter.Action)
	if err != nil {
		return "", err
	}
	resStr += fmt.Sprintf(", index: %v, action: %s", prefix.index, actionName)
	if prefixFilter.Ge != nil {
		resStr += fmt.Sprintf(", ge: %v", *prefixFilter.Ge)
	}
	if prefixFilter.Le != nil {
		resStr += fmt.Sprintf(", le: %v", *prefixFilter.Le)
	}
	resStr += fmt.Sprintf(", prefix: %s", *prefixFilter.Prefix)
	return resStr, nil
}

// for an action of type *string as stored in *datamodel.TransitConnection returns allow/deny
func actionNameStr(action *string) (string, error) {
	actionBool, err := parseActionString(action)
	if err != nil {
		return "", err
	}
	if actionBool {
		return permitAction, nil
	}
	return denyAction, nil
}

// todo: implement
func (tgw *TransitGateway) RulesInConnectivity(src, dst vpcmodel.Node) ([]vpcmodel.RulesInTable, error) {
	return nil, nil
}

func (tgw *TransitGateway) StringPrefixDetails(src, dst vpcmodel.Node, verbose bool) (string, error) {
	prefixes := tgw.prefixesOfSrcDst(src, dst)
	transitEnablesConn := vpcmodel.HasNode(tgw.sourceNodes, src) && vpcmodel.HasNode(tgw.destNodes, dst)
	if verbose {
		tgwRouterFilterDetails, err := tgw.tgwPrefixStr(*prefixes[0]) // todo tmp
		if err != nil {
			return "", err
		}
		action := "blocks"
		if transitEnablesConn {
			action = "allows"
		}
		return fmt.Sprintf("transit gateway %s %s connection with the following prefix\n\t%s\n\n",
			tgw.Name(), action, tgwRouterFilterDetails), nil
	}
	noVerboseStr := fmt.Sprintf("cross-vpc-connection: transit-connection %s of transit-gateway %s ", *(prefixes[0]).tc.Name, tgw.Name()) // todo tmp
	if transitEnablesConn {
		return noVerboseStr + "allows connection" + newline, nil
	}
	return noVerboseStr + "denies connection" + newline, nil
}

// StringDetailsOfRules todo: implement, replace StringPrefixDetails
func (tgw *TransitGateway) StringDetailsOfRules(listRulesInFilter []vpcmodel.RulesInTable) string {
	return ""
}

func (tgw *TransitGateway) prefixesOfSrcDst(src, dst vpcmodel.Node) []*tgwPrefixFilter {
	// <src, dst> routed by tgw given that source is in the tgw,
	// and there is a prefix filter defined for the dst,
	// the relevant prefix filter is determined by match of the Address prefix the dest's node is in (including default)
	prefixes := []*tgwPrefixFilter{}
	if vpcmodel.HasNode(tgw.sourceNodes, src) {
		for _, singleIPBlockPrefix := range tgw.vpcsAPToFiltersOld[dst.VPC().UID()] {
			if dst.IPBlock().ContainedIn(singleIPBlockPrefix.IPBlock) {
				prefixes = append(prefixes, &singleIPBlockPrefix.prefixFilter)
			}
		}
	}
	return prefixes
}

// AppliedFiltersKinds todo: currently not used
func (tgw *TransitGateway) AppliedFiltersKinds() map[string]bool {
	return map[string]bool{vpcmodel.NaclLayer: true, vpcmodel.SecurityGroupLayer: true}
}

func isNodesPair(src, dst vpcmodel.VPCResourceIntf) (res bool, srcNode, dstNode vpcmodel.Node) {
	srcNode, isSrcNode := src.(vpcmodel.Node)
	dstNode, isDstNode := dst.(vpcmodel.Node)
	return isSrcNode && isDstNode, srcNode, dstNode
}

func isSubnetsPair(src, dst vpcmodel.VPCResourceIntf) (res bool, srcSubnet, dstSubnet *Subnet) {
	srcSubnet, isSrcNode := src.(*Subnet)
	dstSubnet, isDstNode := dst.(*Subnet)
	return isSrcNode && isDstNode, srcSubnet, dstSubnet
}

func hasSubnet(listSubnets []*Subnet, subnet *Subnet) bool {
	for _, n := range listSubnets {
		if n.UID() == subnet.UID() {
			return true
		}
	}
	return false
}
