/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
)

const (
	protocolTCP  = "tcp"
	allProtocols = "-1"
	protocolUDP  = "udp"
	protocolICMP = "icmp"
)

type AWSSGAnalyzer struct {
	sgResource         *types.SecurityGroup
	referencedIPblocks []*ipblock.IPBlock
	sgMap              map[string]*commonvpc.SecurityGroup
}

func NewAWSSGAnalyzer(sg *types.SecurityGroup) *AWSSGAnalyzer {
	res := &AWSSGAnalyzer{sgResource: sg}
	return res
}

func (sga *AWSSGAnalyzer) Name() *string {
	return sga.sgResource.GroupName
}

func (sga *AWSSGAnalyzer) getRemoteCidr(ipRanges []types.IpRange, userIDGroupPairs []types.UserIdGroupPair) (
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

// getProtocolAllRule returns rule results corresponding to the provided rule obj with all connections allowed
func (sga *AWSSGAnalyzer) getProtocolAllRule(ruleObj *types.IpPermission, direction string) (
	ruleStr string, ruleRes *commonvpc.SGRule, err error) {
	ruleRes = &commonvpc.SGRule{}
	connStr := "protocol: all"
	remote, err := sga.getRemoteCidr(ruleObj.IpRanges, ruleObj.UserIdGroupPairs)
	if err != nil {
		return "", nil, err
	}
	ruleRes.Remote = commonvpc.NewRuleTarget(remote, "")
	ruleStr = getRuleStr(direction, connStr, ruleRes.Remote.Cidr.String())
	ruleRes.Connections = connection.All()
	return ruleStr, ruleRes, nil
}

// getProtocolTCPUDPRule returns rule results corresponding to the provided rule obj with tcp or udp connection
func (sga *AWSSGAnalyzer) getProtocolTCPUDPRule(ruleObj *types.IpPermission, direction string) (
	ruleStr string, ruleRes *commonvpc.SGRule, err error) {
	minPort := int64(*ruleObj.FromPort)
	maxPort := int64(*ruleObj.ToPort)
	connStr := fmt.Sprintf("protocol: %s,  dstPorts: %d-%d", *ruleObj.IpProtocol, minPort, maxPort)
	remote, err := sga.getRemoteCidr(ruleObj.IpRanges, ruleObj.UserIdGroupPairs)
	if err != nil {
		return "", nil, err
	}
	ruleRes = &commonvpc.SGRule{
		// TODO: src ports can be considered here?
		Connections: commonvpc.GetTCPUDPConns(*ruleObj.IpProtocol,
			connection.MinPort,
			connection.MaxPort,
			minPort,
			maxPort,
		),
		Remote: &commonvpc.RuleTarget{Cidr: remote, SgName: ""},
	}
	ruleStr = getRuleStr(direction, connStr, ruleRes.Remote.Cidr.String())
	return ruleStr, ruleRes, nil
}

func getRuleStr(direction, connStr, ipRanges string) string {
	return fmt.Sprintf("direction: %s,  conns: %s, target: %s\n", direction, connStr, ipRanges)
}

// getProtocolICMPRule returns rule results corresponding to the provided rule obj with icmp connection
func (sga *AWSSGAnalyzer) getProtocolICMPRule(ruleObj *types.IpPermission, direction string) (
	ruleStr string, ruleRes *commonvpc.SGRule, err error) {
	icmpType := int64(*ruleObj.FromPort)
	icmpCode := int64(*ruleObj.ToPort)
	conns := connection.ICMPConnection(icmpType, icmpType, icmpCode, icmpCode)
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

// convertProtocol used to convert protocol numbers to string
func convertProtocol(ipProtocol string) string {
	// currently supports just tcp, udp and icmp
	// todo remove hard coded numbers and support other protocol numbers
	switch ipProtocol {
	case allProtocols:
		return allProtocols
	case "6", protocolTCP:
		return protocolTCP

	case "17", protocolUDP:
		return protocolUDP
	case "1", protocolICMP:
		return protocolICMP
	default:
		return ipProtocol
	}
}

func (sga *AWSSGAnalyzer) GetSGRule(index int) (
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
	*ruleObj.IpProtocol = convertProtocol(*ruleObj.IpProtocol)
	switch *ruleObj.IpProtocol {
	case allProtocols: // all protocols
		ruleStr, ruleRes, err = sga.getProtocolAllRule(&ruleObj, direction)
	case protocolTCP, protocolUDP:
		ruleStr, ruleRes, err = sga.getProtocolTCPUDPRule(&ruleObj, direction)
	case protocolICMP:
		ruleStr, ruleRes, err = sga.getProtocolICMPRule(&ruleObj, direction)
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

func (sga *AWSSGAnalyzer) GetSGRules() (ingressRules, egressRules []*commonvpc.SGRule, err error) {
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

func (sga *AWSSGAnalyzer) SetSGmap(sgMap map[string]*commonvpc.SecurityGroup) {
	sga.sgMap = sgMap
}

func (sga *AWSSGAnalyzer) ReferencedIPblocks() []*ipblock.IPBlock {
	return sga.referencedIPblocks
}

func (sga *AWSSGAnalyzer) GetNumberOfRules() int {
	return len(sga.sgResource.IpPermissions) + len(sga.sgResource.IpPermissionsEgress)
}
