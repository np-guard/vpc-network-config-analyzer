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
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

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
func getFilterAction(rType vpcmodel.RulesType) bool {
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
				Table:       index,
				Rules:       sgRules,
				RulesOfType: rType,
			}
			allowRes = append(allowRes, rulesInSg)
		}
	}
	return allowRes, nil, nil
}

func (sgl *SecurityGroupLayer) StringDetailsOfRules(listRulesInFilter []vpcmodel.RulesInTable) string {
	listRulesInFilterSlice := make([]string, len(listRulesInFilter))
	for i, rulesInFilter := range listRulesInFilter {
		sg := sgl.SgList[rulesInFilter.Table]
		listRulesInFilterSlice[i] = "\t\t" + GetHeaderRulesType(vpcmodel.FilterKindName(sgl.Kind())+" "+sg.Name(), rulesInFilter.RulesOfType) +
			sg.Analyzer.SgAnalyzer.StringRules(rulesInFilter.Rules)
	}
	sort.Strings(listRulesInFilterSlice)
	return strings.Join(listRulesInFilterSlice, "")
}

func (sgl *SecurityGroupLayer) ListFilterWithAction(listRulesInFilter []vpcmodel.RulesInTable) (filters map[string]bool) {
	filters = map[string]bool{}
	for _, rulesInFilter := range listRulesInFilter {
		sg := sgl.SgList[rulesInFilter.Table]
		name := sg.Name()
		filters[name] = getFilterAction(rulesInFilter.RulesOfType)
	}
	return filters
}

func (sgl *SecurityGroupLayer) ReferencedIPblocks() []*ipblock.IPBlock {
	res := []*ipblock.IPBlock{}
	for _, sg := range sgl.SgList {
		res = append(res, sg.Analyzer.SgAnalyzer.ReferencedIPblocks()...)
	}
	return res
}

type SecurityGroup struct {
	vpcmodel.VPCResource
	Analyzer *SGAnalyzer
	// map of SG members, key is IP-address: pairs(address[string], object[NetworkInterface/ReservedIP])
	Members map[string]vpcmodel.Node
}

func (sg *SecurityGroup) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) *connection.Set {
	memberStrAddress, targetIPBlock := sg.getMemberTargetStrAddress(src, dst, isIngress)
	if _, ok := sg.Members[memberStrAddress]; !ok {
		return connection.None() // connectivity not affected by this SG resource - input node is not its member
	}
	return sg.Analyzer.allowedConnectivity(targetIPBlock, ipblock.GetCidrAll(), isIngress)
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
	memberStrAddress, targetIPBlock := sg.getMemberTargetStrAddress(src, dst, isIngress)
	if _, ok := sg.Members[memberStrAddress]; !ok {
		return false, nil, nil // connectivity not affected by this SG resource - input node is not its member
	}
	rules, err = sg.Analyzer.rulesFilterInConnectivity(targetIPBlock, ipblock.GetCidrAll(), conn, isIngress)
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
