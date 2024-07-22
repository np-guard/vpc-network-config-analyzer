/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
)

type SpecificAnalyzer struct {
	sgResource         *types.SecurityGroup
	referencedIPblocks []*ipblock.IPBlock
	sgMap              map[string]*commonvpc.SecurityGroup
}

func NewSpecificAnalyzer(sg *types.SecurityGroup) *SpecificAnalyzer {
	res := &SpecificAnalyzer{sgResource: sg}
	return res
}

func getAllConnSet() *connection.Set {
	return connection.All()
}

func getProperty(p *int64, defaultP int64) int64 {
	if p == nil {
		return defaultP
	}
	return *p
}

func getTCPUDPConns(p string, srcPortMin, srcPortMax, dstPortMin, dstPortMax int64) *connection.Set {
	protocol := netp.ProtocolStringUDP
	if p == commonvpc.ProtocolTCP {
		protocol = netp.ProtocolStringTCP
	}
	return connection.TCPorUDPConnection(protocol, srcPortMin, srcPortMax, dstPortMin, dstPortMax)
}

func (sga *SpecificAnalyzer) Name() *string {
	return sga.sgResource.GroupName
}

func (sga *SpecificAnalyzer) getRemoteCidr(ipRanges []types.IpRange, userIDGroupPairs []types.UserIdGroupPair) (
	remote *ipblock.IPBlock, err error) {
	remote = ipblock.New()
	for i := range ipRanges {
		target, _, err := commonvpc.GetIPBlockResult(ipRanges[i].CidrIp, nil, nil, sga.sgMap)
		if err != nil {
			return nil, err
		}
		remote = remote.Union(target)
	}

	for i := range userIDGroupPairs {
		target, _, err := commonvpc.GetIPBlockResult(nil, nil, userIDGroupPairs[i].GroupId, sga.sgMap)
		if err != nil {
			return nil, err
		}
		remote = remote.Union(target)
	}

	if !remote.IsEmpty() {
		sga.referencedIPblocks = append(sga.referencedIPblocks, remote.Split()...)
	}
	return remote, nil
}

func (sga *SpecificAnalyzer) getProtocolAllRule(ruleObj *types.IpPermission, direction string) (
	ruleStr string, ruleRes *commonvpc.SGRule, err error) {
	ruleRes = &commonvpc.SGRule{}
	connStr := "protocol: all"
	remote, err := sga.getRemoteCidr(ruleObj.IpRanges, ruleObj.UserIdGroupPairs)
	if err != nil {
		return "", nil, err
	}
	ruleRes.Remote = commonvpc.NewRuleTarget(remote, "")
	ruleStr = getRuleStr(direction, connStr, ruleRes.Remote.Cidr.String())
	ruleRes.Connections = getAllConnSet()
	return ruleStr, ruleRes, nil
}

func (sga *SpecificAnalyzer) getProtocolTcpudpRule(ruleObj *types.IpPermission, direction string) (
	ruleStr string, ruleRes *commonvpc.SGRule, err error) {
	minPort := int64(*ruleObj.FromPort)
	maxPort := int64(*ruleObj.ToPort)
	dstPortMin := getProperty(&minPort, connection.MinPort)
	dstPortMax := getProperty(&maxPort, connection.MaxPort)
	dstPorts := fmt.Sprintf("%d-%d", dstPortMin, dstPortMax)
	connStr := fmt.Sprintf("protocol: %s,  dstPorts: %s", *ruleObj.IpProtocol, dstPorts)
	remote, err := sga.getRemoteCidr(ruleObj.IpRanges, ruleObj.UserIdGroupPairs)
	if err != nil {
		return "", nil, err
	}
	ruleRes = &commonvpc.SGRule{
		// TODO: src ports can be considered here?
		Connections: getTCPUDPConns(*ruleObj.IpProtocol,
			connection.MinPort,
			connection.MaxPort,
			dstPortMin,
			dstPortMax,
		),
		Remote: &commonvpc.RuleTarget{Cidr: remote, SgName: ""},
	}
	ruleStr = getRuleStr(direction, connStr, ruleRes.Remote.Cidr.String())
	return ruleStr, ruleRes, nil
}

func getRuleStr(direction, connStr, ipRanges string) string {
	return fmt.Sprintf("direction: %s,  conns: %s, target: %s\n", direction, connStr, ipRanges)
}

func getICMPconn(icmpType, icmpCode *int64) *connection.Set {
	typeMin := getProperty(icmpType, connection.MinICMPType)
	typeMax := getProperty(icmpType, connection.MaxICMPType)
	codeMin := getProperty(icmpCode, connection.MinICMPCode)
	codeMax := getProperty(icmpCode, connection.MaxICMPCode)
	return connection.ICMPConnection(typeMin, typeMax, codeMin, codeMax)
}

func (sga *SpecificAnalyzer) getProtocolIcmpRule(ruleObj *types.IpPermission, direction string) (
	ruleStr string, ruleRes *commonvpc.SGRule, err error) {
	minPort := int64(*ruleObj.FromPort)
	maxPort := int64(*ruleObj.ToPort)
	conns := getICMPconn(&minPort, &maxPort)
	connStr := fmt.Sprintf("protocol: %s,  icmpType: %s", *ruleObj.IpProtocol, conns)
	remote, err := sga.getRemoteCidr(ruleObj.IpRanges, ruleObj.UserIdGroupPairs)
	if err != nil {
		return "", nil, err
	}
	ruleRes = &commonvpc.SGRule{
		Connections: conns,
		Remote:      &commonvpc.RuleTarget{Cidr: remote, SgName: ""},
	}
	ruleStr = getRuleStr(direction, connStr, ruleRes.Remote.Cidr.String())
	return
}

func (sga *SpecificAnalyzer) GetSGRule(index int) (
	ruleStr string, ruleRes *commonvpc.SGRule, isIngress bool, err error) {
	var ruleObj types.IpPermission
	direction := commonvpc.Inbound
	if index < len(sga.sgResource.IpPermissions) {
		isIngress = true
		ruleObj = sga.sgResource.IpPermissions[index]
	} else {
		direction = commonvpc.Outbound
		isIngress = false
		ruleObj = sga.sgResource.IpPermissionsEgress[index-len(sga.sgResource.IpPermissions)]
	}
	switch *ruleObj.IpProtocol {
	case commonvpc.AllProtocols: // all protocols
		ruleStr, ruleRes, err = sga.getProtocolAllRule(&ruleObj, direction)
	case commonvpc.ProtocolTCP:
		ruleStr, ruleRes, err = sga.getProtocolTcpudpRule(&ruleObj, direction)
	case commonvpc.ProtocolUDP:
		ruleStr, ruleRes, err = sga.getProtocolTcpudpRule(&ruleObj, direction)
	case commonvpc.ProtocolICMP:
		ruleStr, ruleRes, err = sga.getProtocolIcmpRule(&ruleObj, direction)
	default:
		return "", nil, false, fmt.Errorf("getSGRule error: unsupported type")
	}
	if err != nil {
		return "", nil, false, err
	}
	ruleRes.Local = ipblock.GetCidrAll()
	ruleRes.Index = index
	return fmt.Sprintf("index: %d, %v", index, ruleStr), ruleRes, isIngress, nil
}

func (sga *SpecificAnalyzer) GetSGrules() (ingressRules, egressRules []*commonvpc.SGRule, err error) {
	ingressRules = []*commonvpc.SGRule{}
	egressRules = []*commonvpc.SGRule{}
	numRules := len(sga.sgResource.IpPermissions) + len(sga.sgResource.IpPermissionsEgress)
	for index := 0; index < numRules; index++ {
		_, ruleObj, isIngress, err := sga.GetSGRule(index)
		if err != nil {
			return nil, nil, err
		}
		if ruleObj == nil {
			continue
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
		strRulesSlice[i] = "\t" + strRule
	}
	sort.Strings(strRulesSlice)
	return strings.Join(strRulesSlice, "")
}

func (sga *SpecificAnalyzer) SetSGmap(sgMap map[string]*commonvpc.SecurityGroup) {
	sga.sgMap = sgMap
}

func (sga *SpecificAnalyzer) ReferencedIPblocks() []*ipblock.IPBlock {
	return sga.referencedIPblocks
}

func (sga *SpecificAnalyzer) GetNumberOfRules() int {
	return len(sga.sgResource.IpPermissions) + len(sga.sgResource.IpPermissionsEgress)
}
