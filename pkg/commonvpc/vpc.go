/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commonvpc

import (
	"errors"
	"fmt"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const EmptyNameError = "empty name for %s indexed %d"

const securityGroup = "security group"

// not used currently for aws , todo: check
type Region struct {
	Name string
}

type Zone struct {
	Name    string
	Cidrs   []string
	IPblock *ipblock.IPBlock
	Vpc     *VPC // TODO: extend: zone can span over multiple VPCs
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
	Vsi string `json:"-"`
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

// Subnet implements vpcmodel.Subnet interface
type Subnet struct {
	vpcmodel.VPCResource
	VPCnodes []vpcmodel.Node  `json:"-"`
	Cidr     string           `json:"-"`
	IPblock  *ipblock.IPBlock `json:"-"`
	// isPublic is relevant only for aws, the user set for each subnet if it public (i.e. - has access to the internet)
	isPublic bool `json:"-"`
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
func (s *Subnet) IsPublic() bool {
	return s.isPublic
}
func (s *Subnet) SetIsPublic(isPublic bool) {
	s.isPublic = isPublic
}

type Vsi struct {
	vpcmodel.VPCResource
	VPCnodes []vpcmodel.Node
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
