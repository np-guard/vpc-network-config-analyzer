/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commonvpc

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/models/pkg/spec"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const EmptyNameError = "empty name for %s indexed %d"
const networkACL = "network ACL"
const securityGroup = "security group"

// not used currently for aws , todo: check
type Region struct {
	Name string
}

func (r *Region) SynthesisResourceName() string {
	return ""
}
func (r *Region) SynthesisKind() spec.ResourceType {
	return ""
}

type Zone struct {
	Name    string
	Cidrs   []string
	IPblock *ipblock.IPBlock
	Vpc     *VPC // TODO: extend: zone can span over multiple VPCs
}

func (z *Zone) SynthesisResourceName() string {
	return ""
}

func (z *Zone) SynthesisKind() spec.ResourceType {
	return ""
}

func (z *Zone) VPC() *VPC {
	return z.Vpc
}

func zoneFromVPCResource(r vpcmodel.VPCResourceIntf) (*Zone, error) {
	if vpc, ok := r.VPC().(*VPC); ok {
		return vpc.GetZoneByName(r.ZoneName())
	}
	return nil, errors.New("error getting VPC from resource object")
}

// NetworkInterface implements vpcmodel.Node interface
type NetworkInterface struct {
	vpcmodel.VPCResource
	vpcmodel.InternalNode
	Vsi               string `json:"-"`
	numberOfNifsInVsi int
}

// used for synthesis output, if number of nifs is > 1 we use just vsi name
func (ni *NetworkInterface) SynthesisResourceName() string {
	if ni.numberOfNifsInVsi == 1 {
		return ni.VPC().Name() + vpcmodel.Deliminator + ni.VsiName()
	}
	return ni.VPC().Name() + vpcmodel.Deliminator + ni.VsiName() + vpcmodel.Deliminator + ni.ResourceName
}

func (ni *NetworkInterface) SynthesisKind() spec.ResourceType {
	// if this nif's vsi has only one nif, we convert it to instance type with name of the instance
	// because the name of the nif will be meaningless for the user if there is one generated nif.
	if ni.numberOfNifsInVsi == 1 {
		return spec.ResourceTypeInstance
	}
	return spec.ResourceTypeNif
}

func (ni *NetworkInterface) VsiName() string {
	return ni.Vsi
}

func (ni *NetworkInterface) Name() string {
	return nameWithBracketsInfo(ni.Vsi, ni.Address())
}

func (ni *NetworkInterface) ExtendedName(c *vpcmodel.VPCConfig) string {
	return ni.ExtendedPrefix(c) + ni.Name()
}

func nameWithBracketsInfo(name, inBrackets string) string {
	return fmt.Sprintf("%s[%s]", name, inBrackets)
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// nodesets elements - implement vpcmodel.NodeSet interface

// VPC implements vpcmodel.VPC
type VPC struct {
	vpcmodel.VPCResource
	VPCnodes  []vpcmodel.Node
	Zones     map[string]*Zone
	VPCregion *Region
	// internalAddressRange is the union of all the vpc's subnets' CIDRs
	InternalAddressRange   *ipblock.IPBlock
	SubnetsList            []*Subnet
	AddressPrefixesIPBlock *ipblock.IPBlock
	AddressPrefixesList    []string
}

func (v *VPC) AddressPrefixes() *ipblock.IPBlock {
	return v.AddressPrefixesIPBlock
}

func (v *VPC) GetZoneByIPBlock(ipb *ipblock.IPBlock) (string, error) {
	for _, z := range v.Zones {
		if ipb.ContainedIn(z.IPblock) {
			return z.Name, nil
		}
	}
	return "", fmt.Errorf("on vpc %s, could not fine zone for ipblock %s", v.Name(), ipb.ToCidrListString())
}

func (v *VPC) GetZoneByName(name string) (*Zone, error) {
	if z, ok := v.Zones[name]; ok {
		return z, nil
	}
	return nil, fmt.Errorf("zone %s not found in vpc %s", name, v.ResourceName)
}

func (v *VPC) Nodes() []vpcmodel.Node {
	return v.VPCnodes
}

func (v *VPC) AddressRange() *ipblock.IPBlock {
	return v.InternalAddressRange
}

func (v *VPC) Region() *Region {
	return v.VPCregion
}

func (v *VPC) Subnets() []*Subnet {
	return v.SubnetsList
}

// SubnetExpose - can the subnet be exposed to the public internet.
// out of the platforms we support at the moment, this is used in AWS and not in IBM
// In AWS each subnet is private or public and only the latter can connect to/from the public internet
// for IBM the value is set to the default - dontCare (in IBM all subnets can connect to the public internet)
type SubnetExpose int

const (
	dontCareExpose SubnetExpose = iota
	privateExpose
	publicExpose
)

// Subnet implements vpcmodel.Subnet interface
type Subnet struct {
	vpcmodel.VPCResource
	VPCnodes     []vpcmodel.Node  `json:"-"`
	Cidr         string           `json:"-"`
	IPblock      *ipblock.IPBlock `json:"-"`
	subnetExpose SubnetExpose
}

func (s *Subnet) CIDR() string {
	return s.Cidr
}

func (s *Subnet) Zone() (*Zone, error) {
	return zoneFromVPCResource(s)
}

func (s *Subnet) Nodes() []vpcmodel.Node {
	return s.VPCnodes
}

func (s *Subnet) AddressRange() *ipblock.IPBlock {
	return s.IPblock
}
func (s *Subnet) IsPrivate() bool {
	// dontcare means that the provider does not allow to set the subnet to be private, IsPrivate() will return false
	return s.subnetExpose == privateExpose
}

// SetIsPrivate() is called only for platforms that support private/public subnets.
// in other cases, the value of s.subnetExpose remain dontcare
func (s *Subnet) SetIsPrivate(isPrivate bool) {
	s.subnetExpose = publicExpose
	if isPrivate {
		s.subnetExpose = privateExpose
	}
}
func (s *Subnet) SynthesisKind() spec.ResourceType {
	return spec.ResourceTypeSubnet
}

// ////////////////////////////////////////////////////////////////////////////////
// privateSubnetRule is the implementation of PrivateSubnetRule
// it holds the information on the influence of the subnet on the connectivity.
// the rule is created only in case that the subnet configuration has influence on the connectivity between src and dst
// i.e. its relevant only for providers that allow private subnets (aws), and one of the nodes is external
type privateSubnetRule struct {
	subnet    vpcmodel.Subnet
	src, dst  vpcmodel.Node
	isIngress bool
}

func newPrivateSubnetRule(subnet vpcmodel.Subnet, src, dst vpcmodel.Node, isIngress bool) vpcmodel.PrivateSubnetRule {
	return &privateSubnetRule{subnet, src, dst, isIngress}
}

// Note that this func is called only when relevant (platform supporting private subnet and connection to/from internet)
func (psr *privateSubnetRule) Deny(isIngress bool) bool {
	return isIngress == psr.isIngress && psr.subnet.IsPrivate()
}

func (psr *privateSubnetRule) String() string {
	switch {
	case psr.Deny(false):
		return fmt.Sprintf("%s will not accept connection from %s, since subnet %s is private\n",
			psr.dst.Name(), psr.src.Name(), psr.subnet.Name())
	case psr.Deny(true):
		return fmt.Sprintf("%s will not connect to %s, since subnet %s is private\n",
			psr.src.Name(), psr.dst.Name(), psr.subnet.Name())
	case !psr.isIngress:
		return fmt.Sprintf("%s can accept connection from %s, since subnet %s is public\n",
			psr.dst.Name(), psr.src.Name(), psr.subnet.Name())
	case psr.isIngress:
		return fmt.Sprintf("%s can connect to %s, since subnet %s is public\n",
			psr.src.Name(), psr.dst.Name(), psr.subnet.Name())
	}
	return ""
}

func (s *Subnet) GetPrivateSubnetRule(src, dst vpcmodel.Node) vpcmodel.PrivateSubnetRule {
	switch {
	case s.subnetExpose == dontCareExpose:
		return nil
	case src.IsExternal():
		return newPrivateSubnetRule(s, src, dst, true)
	case dst.IsExternal():
		return newPrivateSubnetRule(s, src, dst, false)
	}
	return nil
}

// /////////////////////////////////////////////////////////////////////////////////////////

type Vsi struct {
	vpcmodel.VPCResource
	VPCnodes []vpcmodel.Node
}

func (v *Vsi) SynthesisKind() spec.ResourceType {
	return spec.ResourceTypeInstance
}

func (v *Vsi) Zone() (*Zone, error) {
	return zoneFromVPCResource(v)
}

func (v *Vsi) Nodes() []vpcmodel.Node {
	return v.VPCnodes
}

func (v *Vsi) AddressRange() *ipblock.IPBlock {
	return nodesAddressRange(v.VPCnodes)
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

///////////////////////////////////////////////////////////////////////////////////////////////////
// FilterTraffic elements

type NaclLayer struct {
	vpcmodel.VPCResource
	NaclList []*NACL
}

// per-layer connectivity analysis
// compute allowed connectivity based on the NACL resources for all relevant endpoints (subnets)
func (nl *NaclLayer) ConnectivityMap() (map[string]*vpcmodel.IPbasedConnectivityResult, error) {
	res := map[string]*vpcmodel.IPbasedConnectivityResult{} // map from subnet cidr to its connectivity result
	for _, nacl := range nl.NaclList {
		for subnetCidr, subnet := range nacl.Subnets {
			_, resConnectivity := nacl.Analyzer.GeneralConnectivityPerSubnet(subnet)
			// TODO: currently supporting only handling full-range of subnet connectivity-map, not partial range of subnet
			if len(resConnectivity) != 1 {
				return nil, errors.New("unsupported connectivity map with partial subnet ranges per connectivity result")
			}
			subnetKey := subnet.IPblock.ToIPRanges()
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
	for _, nacl := range nl.NaclList {
		for _, subnet := range nacl.Subnets {
			res = append(res, nacl.GeneralConnectivityPerSubnet(subnet))
		}
	}
	sort.Strings(res)
	return strings.Join(res, "\n")
}

func (nl *NaclLayer) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) (*connection.Set, error) {
	res := connection.None()
	for _, nacl := range nl.NaclList {
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
	for index, nacl := range nl.NaclList {
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
	for _, n := range nl.NaclList {
		res = append(res, n.Analyzer.NaclAnalyzer.ReferencedIPblocks()...)
	}
	return res
}

func (nl *NaclLayer) GetRules() ([]vpcmodel.RuleOfFilter, error) {
	resRulesIngress, err1 := nl.getIngressOrEgressRules(true)
	if err1 != nil {
		return nil, err1
	}
	resRulesEgress, err2 := nl.getIngressOrEgressRules(false)
	if err2 != nil {
		return nil, err2
	}
	return append(resRulesIngress, resRulesEgress...), nil
}

func (nl *NaclLayer) getIngressOrEgressRules(isIngress bool) ([]vpcmodel.RuleOfFilter, error) {
	resRules := []vpcmodel.RuleOfFilter{}
	for naclIndx, nacl := range nl.NaclList {
		var naclRules []*NACLRule
		if isIngress {
			naclRules = nacl.Analyzer.IngressRules
		} else {
			naclRules = nacl.Analyzer.EgressRules
		}
		if nacl.Analyzer.NaclAnalyzer.Name() == nil {
			return nil, fmt.Errorf(EmptyNameError, networkACL, naclIndx)
		}
		naclName := *nacl.Analyzer.NaclAnalyzer.Name()
		for _, rule := range naclRules {
			ruleDesc, _, _, _ := nacl.Analyzer.NaclAnalyzer.GetNACLRule(rule.Index)
			resRules = append(resRules, *vpcmodel.NewRuleOfFilter(networkACL, naclName, ruleDesc, naclIndx, rule.Index,
				isIngress, rule.Src, rule.Dst, rule.Connections))
		}
	}
	return resRules, nil
}

func (nl *NaclLayer) GetFiltersAttachedResources() vpcmodel.FiltersAttachedResources {
	resFiltersAttachedResources := vpcmodel.FiltersAttachedResources{}
	for naclIndex, nacl := range nl.NaclList {
		naclName := *nacl.Analyzer.NaclAnalyzer.Name()
		thisFilter := &vpcmodel.Filter{LayerName: networkACL, FilterName: naclName, FilterIndex: naclIndex}
		members := make([]vpcmodel.VPCResourceIntf, len(nacl.Subnets))
		memberIndex := 0
		for _, subnet := range nacl.Subnets {
			members[memberIndex] = subnet
			memberIndex++
		}
		resFiltersAttachedResources[*thisFilter] = members
	}
	return resFiltersAttachedResources
}

type NACL struct {
	vpcmodel.VPCResource
	Subnets  map[string]*Subnet // map of subnets (pair of cidr strings and subnet obj) for which this nacl is applied to
	Analyzer *NACLAnalyzer
}

func (n *NACL) GeneralConnectivityPerSubnet(subnet *Subnet) string {
	res, _ := n.Analyzer.GeneralConnectivityPerSubnet(subnet)
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
	if _, ok := n.Subnets[connectivityInput.subnet.Cidr]; ok {
		connectivityInput.subnetAffectedByNACL = true
	}
	// checking if targetNode is internal, to save a call to ContainedIn for external nodes
	if connectivityInput.targetNode.IsInternal() &&
		connectivityInput.targetNode.IPBlock().ContainedIn(connectivityInput.subnet.IPblock) {
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
	return n.Analyzer.AllowedConnectivity(connectivityInput.subnet, connectivityInput.nodeInSubnet,
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
	allow, deny, err2 = n.Analyzer.rulesFilterInConnectivity(connectivityInput.subnet, connectivityInput.nodeInSubnet,
		connectivityInput.targetNode, conn, isIngress)
	return true, allow, deny, err2
}

func GetHeaderRulesType(filter string, rType vpcmodel.RulesType) string {
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
func GetFilterAction(rType vpcmodel.RulesType) bool {
	switch rType {
	case vpcmodel.BothAllowDeny, vpcmodel.OnlyAllow:
		return true
	default:
		return false
	}
}

// SecurityGroupLayer captures all SG in the vpc config, analyzes connectivity considering all SG resources
type SecurityGroupLayer struct {
	vpcmodel.VPCResource
	SgList []*SecurityGroup
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
	for _, sg := range sgl.SgList {
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
	for index, sg := range sgl.SgList {
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
	for _, sg := range sgl.SgList {
		res = append(res, sg.Analyzer.SgAnalyzer.ReferencedIPblocks()...)
	}
	return res
}

func (sgl *SecurityGroupLayer) GetRules() ([]vpcmodel.RuleOfFilter, error) {
	resRulesIngress, err1 := sgl.getIngressOrEgressRules(true)
	if err1 != nil {
		return nil, err1
	}
	resRulesEgress, err2 := sgl.getIngressOrEgressRules(false)
	if err2 != nil {
		return nil, err2
	}
	return append(resRulesIngress, resRulesEgress...), nil
}

func (sgl *SecurityGroupLayer) getIngressOrEgressRules(isIngress bool) ([]vpcmodel.RuleOfFilter, error) {
	resRules := []vpcmodel.RuleOfFilter{}
	for sgIndex, sg := range sgl.SgList {
		var sgRules []*SGRule
		if isIngress {
			sgRules = sg.Analyzer.ingressRules
		} else {
			sgRules = sg.Analyzer.egressRules
		}
		if sg.Analyzer.SgAnalyzer.Name() == nil {
			return nil, fmt.Errorf(EmptyNameError, securityGroup, sgIndex)
		}
		sgName := *sg.Analyzer.SgAnalyzer.Name()
		for _, ruleOfSG := range sgRules {
			ruleDesc, _, _, _ := sg.Analyzer.SgAnalyzer.GetSGRule(ruleOfSG.Index)
			var srcBlock, dstBlock *ipblock.IPBlock
			if isIngress {
				srcBlock, dstBlock = ruleOfSG.Remote.Cidr, ruleOfSG.Local
			} else {
				srcBlock, dstBlock = ruleOfSG.Local, ruleOfSG.Remote.Cidr
			}
			resRules = append(resRules, *vpcmodel.NewRuleOfFilter(securityGroup, sgName, ruleDesc, sgIndex, ruleOfSG.Index,
				isIngress, srcBlock, dstBlock, ruleOfSG.Connections))
		}
	}
	return resRules, nil
}

func (sgl *SecurityGroupLayer) GetFiltersAttachedResources() vpcmodel.FiltersAttachedResources {
	resFiltersAttachedResources := vpcmodel.FiltersAttachedResources{}
	for sgIndex, sg := range sgl.SgList {
		sgName := *sg.Analyzer.SgAnalyzer.Name()
		thisFilter := &vpcmodel.Filter{LayerName: securityGroup, FilterName: sgName, FilterIndex: sgIndex}
		members := make([]vpcmodel.VPCResourceIntf, len(sg.Members))
		memberIndex := 0
		for _, memberNode := range sg.Members {
			members[memberIndex] = memberNode
			memberIndex++
		}
		resFiltersAttachedResources[*thisFilter] = members
	}
	return resFiltersAttachedResources
}

type SecurityGroup struct {
	vpcmodel.VPCResource
	Analyzer *SGAnalyzer
	// map of SG members, key is IP-address: pairs(address[string], object[NetworkInterface/ReservedIP])
	Members map[string]vpcmodel.Node
}

func (sg *SecurityGroup) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) *connection.Set {
	memberIPBlock, targetIPBlock, memberStrAddress := sg.getMemberTargetStrAddress(src, dst, isIngress)
	if _, ok := sg.Members[memberStrAddress]; !ok {
		return connection.None() // connectivity not affected by this SG resource - input node is not its member
	}
	return sg.Analyzer.allowedConnectivity(targetIPBlock, memberIPBlock, isIngress)
}

// unifiedMembersIPBlock returns an *IPBlock object with union of all members IPBlock
func (sg *SecurityGroup) unifiedMembersIPBlock() (unifiedMembersIPBlock *ipblock.IPBlock) {
	unifiedMembersIPBlock = ipblock.New()
	for _, memberNode := range sg.Members {
		unifiedMembersIPBlock = unifiedMembersIPBlock.Union(memberNode.IPBlock())
	}

	return unifiedMembersIPBlock
}

// rulesFilterInConnectivity list of SG rules contributing to the connectivity
func (sg *SecurityGroup) rulesFilterInConnectivity(src, dst vpcmodel.Node, conn *connection.Set,
	isIngress bool) (tableRelevant bool, rules []int, err error) {
	memberIPBlock, targetIPBlock, memberStrAddress := sg.getMemberTargetStrAddress(src, dst, isIngress)
	if _, ok := sg.Members[memberStrAddress]; !ok {
		return false, nil, nil // connectivity not affected by this SG resource - input node is not its member
	}
	rules, err = sg.Analyzer.rulesFilterInConnectivity(targetIPBlock, memberIPBlock, conn, isIngress)
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
