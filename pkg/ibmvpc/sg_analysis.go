/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"sort"
	"strings"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/logging"
)

type SpecificAnalyzer struct {
	SgResource         *vpc1.SecurityGroup
	sgMap              map[string]*commonvpc.SecurityGroup
	referencedIPblocks []*ipblock.IPBlock
}

func NewSpecificAnalyzer(sg *vpc1.SecurityGroup) *SpecificAnalyzer {
	res := &SpecificAnalyzer{SgResource: sg}
	return res
}

func isIngressRule(direction *string) bool {
	if direction == nil {
		return false
	}
	if *direction == "inbound" {
		return true
	}
	return false
}

func getEmptyConnSet() *connection.Set {
	return connection.None()
}

func getAllConnSet() *connection.Set {
	return connection.All()
}

func (sga *SpecificAnalyzer) Name() *string {
	return sga.SgResource.Name
}

// getIPBlockResult gets an cidr, address or name of the remote/local rule object, and returns it's IPBlock
func (sga *SpecificAnalyzer) getIPBlockResult(cidr, address, name *string) (*ipblock.IPBlock, string, error) {
	var ipBlock *ipblock.IPBlock
	var cidrRes string
	var err error
	switch {
	case cidr != nil:
		ipBlock, err = ipblock.FromCidr(*cidr)
		if err != nil {
			return nil, "", err
		}
		cidrRes = ipBlock.ToCidrList()[0]
	case address != nil:
		ipBlock, err = ipblock.FromIPAddress(*address)
		if err != nil {
			return nil, "", err
		}
		cidrRes = ipBlock.ToCidrList()[0]
	case name != nil:
		ipBlock = ipblock.New()
		if sg, ok := sga.sgMap[*name]; ok {
			for member := range sg.Members {
				memberIPBlock, err := ipblock.FromIPAddress(member)
				if err != nil {
					return nil, "", err
				}
				ipBlock = ipBlock.Union(memberIPBlock)
			}
			cidrRes = strings.Join(ipBlock.ToCidrList(), ",")
		}
	default:
		return nil, "", fmt.Errorf("sg error: getCidrResult - SecurityGroupRule is empty")
	}
	if ipBlock == nil {
		return nil, "", fmt.Errorf("getIPBlockResult err: unexpected nil ipBlock returned")
	}
	if ipBlock.IsEmpty() {
		logging.Debugf("SG rule references an empty IPBlock, rule will be ignored")
	}
	return ipBlock, cidrRes, nil
}

// getRemoteCidr gets remote rule object interface and returns it's IPBlock
func (sga *SpecificAnalyzer) getRemoteCidr(remote vpc1.SecurityGroupRuleRemoteIntf) (target *ipblock.IPBlock,
	cidrRes string, remoteSGName string, err error) {
	// TODO: on actual run from SG example, the type of remoteObj is SecurityGroupRuleRemote and not SecurityGroupRuleRemoteCIDR,
	// even if cidr is defined
	//TODO: handle other remote types:
	// SecurityGroupRuleRemoteIP
	// SecurityGroupRuleRemoteSecurityGroupReference

	// how can infer type of remote from this object?
	// can also be Address or CRN or ...
	if remoteObj, ok := remote.(*vpc1.SecurityGroupRuleRemote); ok {
		target, cidrRes, err = sga.getIPBlockResult(remoteObj.CIDRBlock, remoteObj.Address, remoteObj.Name)
		if err != nil {
			return nil, "", "", err
		}
		if remoteObj.Name != nil {
			remoteSGName = *remoteObj.Name
		}
	}

	if !target.IsEmpty() {
		sga.referencedIPblocks = append(sga.referencedIPblocks, target.Split()...)
	}
	return target, cidrRes, remoteSGName, nil
}

func getDefaultLocal() (ipb *ipblock.IPBlock, cidr string) {
	return ipblock.GetCidrAll(), ipblock.CidrAll
}

// getRemoteCidr gets local rule object interface and returns it's IPBlock
func (sga *SpecificAnalyzer) getLocalCidr(local vpc1.SecurityGroupRuleLocalIntf) (*ipblock.IPBlock, string, error) {
	var localIP *ipblock.IPBlock
	var cidrRes string
	var err error
	if localObj, ok := local.(*vpc1.SecurityGroupRuleLocal); ok {
		localIP, cidrRes, err = sga.getIPBlockResult(localObj.CIDRBlock, localObj.Address, nil)
		if err != nil {
			return nil, "", err
		}

		if localIP == nil || cidrRes == "" {
			// support old config files with missing local field
			localIP, cidrRes = getDefaultLocal()
		}
	}
	if localIP == nil || cidrRes == "" {
		// support old config files with missing local field
		localIP, cidrRes = getDefaultLocal()
	}
	return localIP, cidrRes, nil
}

func (sga *SpecificAnalyzer) getProtocolAllRule(ruleObj *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolAll) (
	ruleStr string, ruleRes *commonvpc.SGRule, isIngress bool, err error) {
	ruleRes = &commonvpc.SGRule{}
	direction := *ruleObj.Direction
	isIngress = isIngressRule(ruleObj.Direction)
	protocol := *ruleObj.Protocol
	remoteCidr, localCidr, remoteSGName := "", "", ""
	var remote, local *ipblock.IPBlock
	remote, remoteCidr, remoteSGName, err = sga.getRemoteCidr(ruleObj.Remote)
	if err != nil {
		return "", nil, false, err
	}
	local, localCidr, err = sga.getLocalCidr(ruleObj.Local)
	if err != nil {
		return "", nil, false, err
	}
	connStr := fmt.Sprintf("protocol: %s", protocol)
	ruleStr = getRuleStr(direction, connStr, remoteCidr, remoteSGName, localCidr)
	ruleRes.Remote = commonvpc.NewRuleTarget(remote, remoteSGName)
	ruleRes.Local = local
	ruleRes.Connections = getAllConnSet()
	return ruleStr, ruleRes, isIngress, nil
}

func (sga *SpecificAnalyzer) getProtocolTcpudpRule(ruleObj *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp) (
	ruleStr string, ruleRes *commonvpc.SGRule, isIngress bool, err error) {
	direction := *ruleObj.Direction
	isIngress = isIngressRule(ruleObj.Direction)
	remote, remoteCidr, remoteSGName, err := sga.getRemoteCidr(ruleObj.Remote)
	if err != nil {
		return "", nil, false, err
	}
	local, localCidr, err := sga.getLocalCidr(ruleObj.Local)
	if err != nil {
		return "", nil, false, err
	}
	dstPortMin := getProperty(ruleObj.PortMin, connection.MinPort)
	dstPortMax := getProperty(ruleObj.PortMax, connection.MaxPort)
	dstPorts := fmt.Sprintf("%d-%d", dstPortMin, dstPortMax)
	connStr := fmt.Sprintf("protocol: %s,  dstPorts: %s", *ruleObj.Protocol, dstPorts)
	ruleStr = getRuleStr(direction, connStr, remoteCidr, remoteSGName, localCidr)
	ruleRes = &commonvpc.SGRule{
		// TODO: src ports can be considered here?
		Connections: getTCPUDPConns(*ruleObj.Protocol,
			connection.MinPort,
			connection.MaxPort,
			dstPortMin,
			dstPortMax,
		),
		Remote: commonvpc.NewRuleTarget(remote, remoteSGName),
		Local:  local,
	}
	return ruleStr, ruleRes, isIngress, nil
}

func getRuleStr(direction, connStr, remoteCidr, remoteSGName, localCidr string) string {
	remoteSGStr := remoteCidr
	if remoteSGName != "" {
		remoteSGStr = remoteSGName + " (" + remoteCidr + ")"
	}
	return fmt.Sprintf("direction: %s,  conns: %s, remote: %s, local: %s\n", direction, connStr, remoteSGStr, localCidr)
}

func getICMPconn(icmpType, icmpCode *int64) *connection.Set {
	typeMin := getProperty(icmpType, connection.MinICMPType)
	typeMax := getProperty(icmpType, connection.MaxICMPType)
	codeMin := getProperty(icmpCode, connection.MinICMPCode)
	codeMax := getProperty(icmpCode, connection.MaxICMPCode)
	return connection.ICMPConnection(typeMin, typeMax, codeMin, codeMax)
}

func (sga *SpecificAnalyzer) getProtocolIcmpRule(ruleObj *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp) (
	ruleStr string, ruleRes *commonvpc.SGRule, isIngress bool, err error) {
	remote, remoteCidr, remoteSGName, err := sga.getRemoteCidr(ruleObj.Remote)
	if err != nil {
		return
	}
	local, localCidr, err := sga.getLocalCidr(ruleObj.Local)
	if err != nil {
		return
	}
	conns := getICMPconn(ruleObj.Type, ruleObj.Code)
	connStr := fmt.Sprintf("protocol: %s,  icmpType: %s", *ruleObj.Protocol, conns)
	ruleStr = getRuleStr(*ruleObj.Direction, connStr, remoteCidr, remoteSGName, localCidr)
	ruleRes = &commonvpc.SGRule{
		Connections: conns,
		Remote:      commonvpc.NewRuleTarget(remote, remoteSGName),
		Local:       local,
	}
	isIngress = isIngressRule(ruleObj.Direction)
	return
}

func (sga *SpecificAnalyzer) GetSGRule(index int) (
	ruleStr string, ruleRes *commonvpc.SGRule, isIngress bool, err error) {
	rule := sga.SgResource.Rules[index]
	switch ruleObj := rule.(type) {
	case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolAll:
		ruleStr, ruleRes, isIngress, err = sga.getProtocolAllRule(ruleObj)
	case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp:
		ruleStr, ruleRes, isIngress, err = sga.getProtocolTcpudpRule(ruleObj)
	case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp:
		ruleStr, ruleRes, isIngress, err = sga.getProtocolIcmpRule(ruleObj)
	default:
		return "", nil, false, fmt.Errorf("getSGRule error: unsupported type")
	}
	if err != nil {
		return "", nil, false, err
	}
	ruleRes.Index = index
	return fmt.Sprintf("index: %d, %v", index, ruleStr), ruleRes, isIngress, nil
}

func (sga *SpecificAnalyzer) GetSGrules() (ingressRules, egressRules []*commonvpc.SGRule, err error) {
	ingressRules = []*commonvpc.SGRule{}
	egressRules = []*commonvpc.SGRule{}
	for index := range sga.SgResource.Rules {
		_, ruleObj, isIngress, err := sga.GetSGRule(index)
		if err != nil {
			return nil, nil, err
		}
		if ruleObj == nil {
			continue
		}
		if ruleObj.Remote.Cidr.IsEmpty() && ruleObj.Remote.SgName != "" {
			logging.Warnf("in SG %s, rule index %d: could not find remote SG %s or its attached network interfaces",
				*sga.SgResource.Name, index, ruleObj.Remote.SgName)
		}
		if isIngress {
			ingressRules = append(ingressRules, ruleObj)
		} else {
			egressRules = append(egressRules, ruleObj)
		}
	}
	return ingressRules, egressRules, nil
}

// StringRules returns a string with the details of the specified rules
func (sga *SpecificAnalyzer) StringRules(rules []int) string {
	strRulesSlice := make([]string, len(rules))
	for i, ruleIndex := range rules {
		strRule, _, _, err := sga.GetSGRule(ruleIndex)
		if err != nil {
			return ""
		}
		strRulesSlice[i] = "\t\t\t" + strRule
	}
	sort.Strings(strRulesSlice)
	return strings.Join(strRulesSlice, "")
}

func (sga *SpecificAnalyzer) ReferencedIPblocks() []*ipblock.IPBlock {
	return sga.referencedIPblocks
}

func (sga *SpecificAnalyzer) SetSGmap(sgMap map[string]*commonvpc.SecurityGroup) {
	sga.sgMap = sgMap
}

func (sga *SpecificAnalyzer) GetNumberOfRules() int {
	return len(sga.SgResource.Rules)
}
