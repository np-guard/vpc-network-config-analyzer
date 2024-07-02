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
	if p == protocolTCP {
		protocol = netp.ProtocolStringTCP
	}
	return connection.TCPorUDPConnection(protocol, srcPortMin, srcPortMax, dstPortMin, dstPortMax)
}

func (sga *SpecificAnalyzer) getProtocolAllRule(ruleObj *types.IpPermission, direction string) (
	ruleStr string, ruleRes *commonvpc.SGRule, err error) {
	ruleRes = &commonvpc.SGRule{}
	connStr := "protocol: all"
	remote := ipblock.New()
	for i := range ruleObj.IpRanges {
		ipRange, err := ipblock.FromCidr(*ruleObj.IpRanges[i].CidrIp)
		if err != nil {
			return "", nil, err
		}
		remote = remote.Union(ipRange)
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
	remote := ipblock.New()
	for i := range ruleObj.IpRanges {
		ipRange, err := ipblock.FromCidr(*ruleObj.IpRanges[i].CidrIp)
		if err != nil {
			return "", nil, err
		}
		remote = remote.Union(ipRange)
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
	return fmt.Sprintf("direction: %s,  conns: %s, ipRanges: %s\n", direction, connStr, ipRanges)
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
	remote := ipblock.New()
	for i := range ruleObj.IpRanges {
		ipRange, err := ipblock.FromCidr(*ruleObj.IpRanges[i].CidrIp)
		if err != nil {
			return "", nil, err
		}
		remote = remote.Union(ipRange)
	}
	ruleStr = getRuleStr(direction, connStr, ruleRes.Remote.Cidr.String())
	ruleRes = &commonvpc.SGRule{
		Connections: conns,
		Remote:      &commonvpc.RuleTarget{Cidr: remote, SgName: ""},
	}
	return
}

func (sga *SpecificAnalyzer) GetSGRule(index int) (
	ruleStr string, ruleRes *commonvpc.SGRule, isIngress bool, err error) {
	var ruleObj types.IpPermission
	direction := inbound
	if index < len(sga.sgResource.IpPermissions) {
		isIngress = true
		ruleObj = sga.sgResource.IpPermissions[index]
	} else {
		direction = outbound
		isIngress = false
		ruleObj = sga.sgResource.IpPermissionsEgress[index-len(sga.sgResource.IpPermissions)]
	}
	switch *ruleObj.IpProtocol {
	case allProtocols: // all protocols
		ruleStr, ruleRes, err = sga.getProtocolAllRule(&ruleObj, direction)
	case protocolTCP:
		ruleStr, ruleRes, err = sga.getProtocolTcpudpRule(&ruleObj, direction)
	case protocolUDP:
		ruleStr, ruleRes, err = sga.getProtocolTcpudpRule(&ruleObj, direction)
	case protocolICMP:
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
