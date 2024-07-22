/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/logging"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const doubleTab = "\t\t" // todo delete when no longer used
const emptyNameError = "empty name for %s indexed %d"

const securityGroup = "security group"
const networkACL = "network ACL"

///////////////////////////////////////////////////////////////////////////////////////////////////

func nameWithBracketsInfo(name, inBrackets string) string {
	return fmt.Sprintf("%s[%s]", name, inBrackets)
}

type Region struct {
	name string
}

type Zone struct {
	name    string
	cidrs   []string
	ipblock *ipblock.IPBlock
	vpc     *VPC // TODO: extend: zone can span over multiple VPCs
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
	return nameWithBracketsInfo(r.vpe, r.Address())
}

func (r *ReservedIP) ExtendedName(c *vpcmodel.VPCConfig) string {
	return r.ExtendedPrefix(c) + r.Name()
}

// PrivateIP implements vpcmodel.Node interface
type PrivateIP struct {
	vpcmodel.VPCResource
	vpcmodel.InternalNode
	loadBalancer *LoadBalancer
	// Since not all the LB has a private IP, we create a potential Private IP at the LB's subnets that do not have one.
	// original - does the private IP was originally at the config file, or is it a potential one
	original bool
	// the potential block which the pip was created for:
	block *ipblock.IPBlock
}

func (pip *PrivateIP) Name() string {
	kind := "LB private IP"
	address := pip.Address()
	if !pip.original {
		kind = "Potential " + kind
		// todo - use ToRangesListString() instead of ListToPrint()
		address = strings.Join(pip.block.ListToPrint(), ",")
	}
	name := nameWithBracketsInfo(pip.loadBalancer.ResourceName, kind)
	return nameWithBracketsInfo(name, address)
}

func (pip *PrivateIP) ExtendedName(c *vpcmodel.VPCConfig) string {
	return pip.ExtendedPrefix(c) + pip.Name()
}

// AbstractedToNodeSet returns the pip load balancer if it was abstracted
func (pip *PrivateIP) AbstractedToNodeSet() vpcmodel.NodeSet {
	if pip.loadBalancer.AbstractionInfo() != nil {
		return pip.loadBalancer
	}
	return nil
}
func (pip *PrivateIP) RepresentedByAddress() bool {
	return false
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
	return nameWithBracketsInfo(ni.vsi, ni.Address())
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
	return nameWithBracketsInfo(n.ResourceName, n.Address())
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

func (v *VPC) getZoneByIPBlock(ipb *ipblock.IPBlock) (string, error) {
	for _, z := range v.zones {
		if ipb.ContainedIn(z.ipblock) {
			return z.name, nil
		}
	}
	return "", fmt.Errorf("on vpc %s, could not fine zone for ipblock %s", v.Name(), ipb.ToCidrListString())
}

func (v *VPC) Region() *Region {
	return v.region
}

func (v *VPC) AddressPrefixes() *ipblock.IPBlock {
	return v.addressPrefixesIPBlock
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

// LoadBalancerPool //////////////////////////////////////////
// Load Balancer
// the nodes are the private IPs
// the listeners hold the pools that holds the backend servers (aka pool members)
type LoadBalancerPool []vpcmodel.Node
type LoadBalancerListener []LoadBalancerPool

type LoadBalancer struct {
	vpcmodel.VPCResource
	nodes     []vpcmodel.Node
	listeners []LoadBalancerListener
	// abstractionInfo holds the information the relevant for the abstraction of the load balancer
	abstractionInfo *vpcmodel.AbstractionInfo
}

// for LB we add the kind to the name, to make it clear in the reports
func (lb *LoadBalancer) nameWithKind() string {
	return nameWithBracketsInfo(lb.ResourceName, lb.Kind())
}
func (lb *LoadBalancer) ExtendedName(c *vpcmodel.VPCConfig) string {
	return lb.ExtendedPrefix(c) + lb.nameWithKind()
}

func (lb *LoadBalancer) Nodes() []vpcmodel.Node {
	return lb.nodes
}
func (lb *LoadBalancer) AddressRange() *ipblock.IPBlock {
	return nodesAddressRange(lb.nodes)
}

func (lb *LoadBalancer) GetLoadBalancerRule(src, dst vpcmodel.Node) vpcmodel.LoadBalancerRule {
	// currently, we do not allow connections from privateIP to a destination that is not a pool member
	if slices.Contains(lb.Nodes(), src) {
		if !slices.Contains(lb.members(), dst) {
			return NewLoadBalancerRule(lb, true, src, dst)
		}
		return NewLoadBalancerRule(lb, false, src, dst)
	}
	return nil
}

// for now the listeners hold the pools that holds the backend servers (aka pool members)
func (lb *LoadBalancer) members() []vpcmodel.Node {
	res := []vpcmodel.Node{}
	for _, l := range lb.listeners {
		for _, pool := range l {
			res = append(res, pool...)
		}
	}
	return res
}

// lb is per vpc and not per zone...
func (lb *LoadBalancer) Zone() (*Zone, error) {
	return nil, nil
}

func (lb *LoadBalancer) SetAbstractionInfo(abstractionInfo *vpcmodel.AbstractionInfo) {
	lb.abstractionInfo = abstractionInfo
}
func (lb *LoadBalancer) AbstractionInfo() *vpcmodel.AbstractionInfo {
	return lb.abstractionInfo
}

// ////////////////////////////////////////////////////////////////////////////////
// LoadBalancerRule is a rule applied to all private IPs of a given load balancer:
// these private IPs can only connect to pool members of the load balancer.
type LoadBalancerRule struct {
	// the relevant load balancer:
	lb *LoadBalancer
	//	deny- true if src is pip, and dst is not pool member:
	deny     bool
	src, dst vpcmodel.Node
}

func NewLoadBalancerRule(lb *LoadBalancer, deny bool, src, dst vpcmodel.Node) vpcmodel.LoadBalancerRule {
	return &LoadBalancerRule{lb, deny, src, dst}
}

func (lbr *LoadBalancerRule) Deny() bool { return lbr.deny }

func (lbr *LoadBalancerRule) String() string {
	if lbr.Deny() {
		return fmt.Sprintf("%s will not connect to %s, since it is not its pool member\n",
			lbr.lb.nameWithKind(), lbr.dst.Name())
	}
	return fmt.Sprintf("%s may initiate a connection to %s, which is one of its pool members\n",
		lbr.lb.nameWithKind(), lbr.dst.Name())
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
		TableIndex:  filterIndex,
		Rules:       *rules,
		RulesOfType: rType,
	}
	*resRulesInFilter = append(*resRulesInFilter, rulesInNacl)
}

func (nl *NaclLayer) ReferencedIPblocks() []*ipblock.IPBlock {
	res := []*ipblock.IPBlock{}
	for _, n := range nl.naclList {
		res = append(res, n.analyzer.referencedIPblocks...)
	}
	return res
}

func (nl *NaclLayer) GetRules() ([]vpcmodel.RuleOfFilter, error) {
	resRules := []vpcmodel.RuleOfFilter{}
	for naclIndx, nacl := range nl.naclList {
		naclRules := nacl.analyzer.egressRules
		naclRules = append(naclRules, nacl.analyzer.ingressRules...)
		if nacl.analyzer.naclResource.Name == nil {
			return nil, fmt.Errorf(emptyNameError, networkACL, naclIndx)
		}
		naclName := *nacl.analyzer.naclResource.Name
		for _, rule := range naclRules {
			ruleBlocks := []*ipblock.IPBlock{rule.src, rule.dst}
			ruleDesc, _, _, _ := nacl.analyzer.getNACLRule(rule.index)
			resRules = append(resRules, *vpcmodel.NewRuleOfFilter(networkACL, naclName, ruleDesc, naclIndx, rule.index,
				ruleBlocks))
		}
	}
	return resRules, nil
}

func (nl *NaclLayer) GetTables() ([]vpcmodel.Table, error) {
	tables := make([]vpcmodel.Table, len(nl.naclList))
	for i, table := range nl.naclList {
		tables[i] = vpcmodel.Table{LayerName: vpcmodel.NaclLayer, FilterName: table.Name(), FilterIndex: i}
	}
	return tables, nil
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
				TableIndex:  index,
				Rules:       sgRules,
				RulesOfType: rType,
			}
			allowRes = append(allowRes, rulesInSg)
		}
	}
	return allowRes, nil, nil
}

func (sgl *SecurityGroupLayer) ReferencedIPblocks() []*ipblock.IPBlock {
	res := []*ipblock.IPBlock{}
	for _, sg := range sgl.sgList {
		res = append(res, sg.analyzer.referencedIPblocks...)
	}
	return res
}

func (sgl *SecurityGroupLayer) GetRules() ([]vpcmodel.RuleOfFilter, error) {
	resRules := []vpcmodel.RuleOfFilter{}
	for sgIndx, sg := range sgl.sgList {
		sgRules := sg.analyzer.egressRules
		sgRules = append(sgRules, sg.analyzer.ingressRules...)
		if sg.analyzer.sgResource.Name == nil {
			return nil, fmt.Errorf(emptyNameError, securityGroup, sgIndx)
		}
		sgName := *sg.analyzer.sgResource.Name
		for _, rule := range sgRules {
			ruleBlocks := []*ipblock.IPBlock{rule.remote.cidr}
			if rule.local != nil {
				ruleBlocks = append(ruleBlocks, rule.local)
			}
			ruleDesc, _, _, _ := sg.analyzer.getSGRule(rule.index)
			resRules = append(resRules, *vpcmodel.NewRuleOfFilter(securityGroup, sgName, ruleDesc, sgIndx, rule.index,
				ruleBlocks))
		}
	}
	return resRules, nil
}

func (sgl *SecurityGroupLayer) GetTables() ([]vpcmodel.Table, error) {
	tables := make([]vpcmodel.Table, len(sgl.sgList))
	for i, table := range sgl.sgList {
		tables[i] = vpcmodel.Table{LayerName: vpcmodel.SecurityGroupLayer, FilterName: table.Name(), FilterIndex: i}
	}
	return tables, nil
}

type SecurityGroup struct {
	vpcmodel.VPCResource
	analyzer *SGAnalyzer
	// map of SG members, key is IP-address: pairs(address[string], object[NetworkInterface/ReservedIP])
	members map[string]vpcmodel.Node
}

func (sg *SecurityGroup) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) *connection.Set {
	memberIPBlock, targetIPBlock, memberStrAddress := sg.getMemberTargetStrAddress(src, dst, isIngress)
	if _, ok := sg.members[memberStrAddress]; !ok {
		return connection.None() // connectivity not affected by this SG resource - input node is not its member
	}
	return sg.analyzer.AllowedConnectivity(targetIPBlock, memberIPBlock, isIngress)
}

// unifiedMembersIPBlock returns an *IPBlock object with union of all members IPBlock
func (sg *SecurityGroup) unifiedMembersIPBlock() (unifiedMembersIPBlock *ipblock.IPBlock) {
	unifiedMembersIPBlock = ipblock.New()
	for _, memberNode := range sg.members {
		unifiedMembersIPBlock = unifiedMembersIPBlock.Union(memberNode.IPBlock())
	}

	return unifiedMembersIPBlock
}

// rulesFilterInConnectivity list of SG rules contributing to the connectivity
func (sg *SecurityGroup) rulesFilterInConnectivity(src, dst vpcmodel.Node, conn *connection.Set,
	isIngress bool) (tableRelevant bool, rules []int, err error) {
	memberIPBlock, targetIPBlock, memberStrAddress := sg.getMemberTargetStrAddress(src, dst, isIngress)
	if _, ok := sg.members[memberStrAddress]; !ok {
		return false, nil, nil // connectivity not affected by this SG resource - input node is not its member
	}
	rules, err = sg.analyzer.rulesFilterInConnectivity(targetIPBlock, memberIPBlock, conn, isIngress)
	return true, rules, err
}

func (sg *SecurityGroup) getMemberTargetStrAddress(src, dst vpcmodel.Node,
	isIngress bool) (memberIPBlock, targetIPBlock *ipblock.IPBlock, memberStrAddress string) {
	var member, target vpcmodel.Node
	if isIngress {
		member, target = dst, src
	} else {
		member, target = src, dst
	}
	// TODO: member is expected to be internal node (validate?) [could use member.(vpcmodel.InternalNodeIntf).Address()]
	return member.IPBlock(), target.IPBlock(), member.CidrOrAddress()
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

func (fip *FloatingIP) RulesInConnectivity(src, dst vpcmodel.Node) []vpcmodel.RulesInTable {
	return nil
}

func (fip *FloatingIP) StringOfRouterRules(listRulesInFilter []vpcmodel.RulesInTable,
	verbose bool) (string, error) {
	return "", nil
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

func (pgw *PublicGateway) RulesInConnectivity(src, dst vpcmodel.Node) []vpcmodel.RulesInTable {
	return nil
}

func (pgw *PublicGateway) StringOfRouterRules(listRulesInFilter []vpcmodel.RulesInTable,
	verbose bool) (string, error) {
	return "", nil
}

type TransitGateway struct {
	vpcmodel.VPCResource

	// vpcs are the VPCs connected by a TGW
	vpcs []*VPC

	// list of all transit connections (not only those relevant to this TransitGateway)
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

	// maps each VPC UID to the details of the matching filters
	// these details includes map of each relevant IPBlock to the transit connection (its index in the tgwConnList)
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

func isPairRelevantToTGW(src, dst vpcmodel.VPCResourceIntf) bool {
	return !(src.IsExternal() || dst.IsExternal()) && src.VPC().UID() != dst.VPC().UID()
}

func (tgw *TransitGateway) AllowedConnectivity(src, dst vpcmodel.VPCResourceIntf) (*connection.Set, error) {
	if !isPairRelevantToTGW(src, dst) {
		logging.Debugf("pair not relevant to TGW")
		return connection.None(), nil
	}
	if areNodes, src1, dst1 := isNodesPair(src, dst); areNodes {
		if vpcmodel.HasNode(tgw.sourceNodes, src1) && vpcmodel.HasNode(tgw.destNodes, dst1) {
			logging.Debugf("tgw enables this connectivity")
			return connection.All(), nil
		}
		logging.Debugf("tgw disables this connectivity")
		return connection.None(), nil
	}
	if areSubnets, src1, dst1 := isSubnetsPair(src, dst); areSubnets {
		if hasSubnet(tgw.sourceSubnets, src1) && hasSubnet(tgw.destSubnets, dst1) {
			return connection.All(), nil
		}
		return connection.None(), nil
	}

	logging.Debugf("err")
	return nil, errors.New("TransitGateway.AllowedConnectivity() expected src and dst to be two nodes or two subnets")
}

func (tgw *TransitGateway) RouterDefined(src, dst vpcmodel.Node) bool {
	if !isPairRelevantToTGW(src, dst) {
		return false
	}

	// if both src and dst nodes are within tgw.sourceNodes, it means that they are both within VPCs attached to this TGW
	// note that tgw.destNodes does not necessarily contain all these nodes, due to prefix filters
	return vpcmodel.HasNode(tgw.sourceNodes, src) && vpcmodel.HasNode(tgw.sourceNodes, dst)
}

// gets a string description of prefix indexed "index" from TransitGateway tgw
//
//nolint:gocritic // no need to name return values. too short
func prefixDefaultStr(tc *datamodel.TransitConnection) (string, string, error) {
	actionName, err := actionNameStr(tc.PrefixFiltersDefault)
	if err != nil {
		return "", "", err
	}
	return fmt.Sprintf("default prefix,  action: %s", actionName), actionName, nil
}

func (tgw *TransitGateway) tgwPrefixStr(tc *datamodel.TransitConnection,
	prefixIndx int) (resStr, actionName string, err error) {
	// Array of prefix route filters for a transit gateway connection. This is order dependent with those first in the
	// array being applied first, and those at the end of the array is applied last, or just before the default.
	if prefixIndx == defaultPrefixFilter { // default
		defaultStr, actionName, err := prefixDefaultStr(tc)
		if err != nil {
			return "", "", err
		}
		return resStr + defaultStr, actionName, nil
	}
	if len(tc.PrefixFilters) < prefixIndx+1 {
		return "", "", fmt.Errorf("np-guard error: prefix index %d does not exists in transit connection %s of transit gateway %s",
			prefixIndx, *tc.Name, tgw.Name())
	}
	prefixFilter := tc.PrefixFilters[prefixIndx]
	actionName, err = actionNameStr(prefixFilter.Action)
	if err != nil {
		return "", "", err
	}
	resStr += fmt.Sprintf("index: %v, action: %s", prefixIndx, actionName)
	if prefixFilter.Ge != nil {
		resStr += fmt.Sprintf(", ge: %v", *prefixFilter.Ge)
	}
	if prefixFilter.Le != nil {
		resStr += fmt.Sprintf(", le: %v", *prefixFilter.Le)
	}
	resStr += fmt.Sprintf(", prefix: %s", *prefixFilter.Prefix)
	return resStr, actionName, nil
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

// RulesInConnectivity returns the prefix filters relevant for <src, dst>.
// src/dst could be a cidr, so for a single <src,dst> query there could be more than one relevant prefix filter
// (in a single transit connection)
// However, each src/dst maps to a set of endpoints (Nodes) and the query is for the Cartesian product of these.
// Specifically, this functionality is between <src, dst> where each is a single endpoint (single IP addr)
// and prefix filter rules do not include protocol or ports (unlike nacls and sgs)
// Thus, for each such <src, dst> there is a single prefix filter
func (tgw *TransitGateway) RulesInConnectivity(src, dst vpcmodel.Node) []vpcmodel.RulesInTable {
	// <src, dst> routed by tgw given that source is in the tgw, and there is a prefix filter defined for the dst,
	// the relevant prefix filter is determined by match of the Address prefix the dest's node is in (including default)
	// Note, again, that for each (src, dst vpcmodel.Node) there is a single prefix filter
	if vpcmodel.HasNode(tgw.sourceNodes, src) {
		for ipBlock, transitConnectionPrefixes := range tgw.vpcsAPToPrefixRules[dst.VPC().UID()] {
			if dst.IPBlock().Overlap(ipBlock) {
				return []vpcmodel.RulesInTable{transitConnectionPrefixes}
			}
		}
	}
	return nil // should never get here
}

func (tgw *TransitGateway) StringOfRouterRules(listRulesInTransitConns []vpcmodel.RulesInTable, verbose bool) (string, error) {
	strRes := []string{}
	for _, prefixesInTransitConn := range listRulesInTransitConns {
		transitConn := tgw.tgwConnList[prefixesInTransitConn.TableIndex]
		if verbose {
			verboseStr, err := tgw.stringPrefixFiltersVerbose(transitConn, prefixesInTransitConn)
			if err != nil {
				return "", err
			}
			strRes = append(strRes, verboseStr...)
		} else {
			strRes = append(strRes, tgw.stringPrefixFiltersNoVerbose(transitConn, prefixesInTransitConn.RulesOfType))
		}
	}
	sort.Strings(strRes)
	return strings.Join(strRes, "\n") + "\n", nil
}

// given a transit connection and a list of the relevant prefix in the connections, prints the relevant prefix details
func (tgw *TransitGateway) stringPrefixFiltersVerbose(transitConn *datamodel.TransitConnection,
	prefixesInTransitConn vpcmodel.RulesInTable) ([]string, error) {
	strRes := []string{}
	for _, prefixInTransConnIndx := range prefixesInTransitConn.Rules {
		thisPrefixStr := ""
		tgwRouterFilterDetails, actionName, err := tgw.tgwPrefixStr(transitConn, prefixInTransConnIndx)
		if err != nil {
			return nil, err
		}
		action := ""
		if actionName == permitAction {
			action = "allows"
		} else {
			action = "blocks"
		}
		thisPrefixStr = fmt.Sprintf("\ttransit gateway %s %s connection via transit connection %s "+
			"with the following prefix filter\n%s%s\n", tgw.Name(), action, *transitConn.Name,
			doubleTab, tgwRouterFilterDetails)
		strRes = append(strRes, thisPrefixStr)
	}
	return strRes, nil
}

// given a transit connection and the effect (onlyDeny/onlyAllow) of this transit gateway on queried <src, dst> ,
// prints a matching non-verbose header
func (tgw *TransitGateway) stringPrefixFiltersNoVerbose(transitConn *datamodel.TransitConnection,
	rulesType vpcmodel.RulesType) string {
	noVerboseStr := fmt.Sprintf("cross-vpc-connection: transit-connection %s of transit-gateway %s ", *transitConn.Name, tgw.Name())
	switch rulesType {
	case vpcmodel.OnlyAllow:
		return noVerboseStr + "allows connection"
	case vpcmodel.OnlyDeny:
		return noVerboseStr + "denies connection"
	}
	return "" // should never get here
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
