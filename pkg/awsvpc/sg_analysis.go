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

type AwsSgAnalyzer struct {
	sgResource         *types.SecurityGroup
	referencedIPblocks []*ipblock.IPBlock
	sgMap              map[string]*commonvpc.SecurityGroup
}

func NewAwsSgAnalyzer(sg *types.SecurityGroup) *AwsSgAnalyzer {
	res := &AwsSgAnalyzer{sgResource: sg}
	return res
}

func (sga *AwsSgAnalyzer) Name() *string {
	return sga.sgResource.GroupName
}

func (sga *AwsSgAnalyzer) getRemoteCidr(ipRanges []types.IpRange, userIDGroupPairs []types.UserIdGroupPair) (
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
func (sga *AwsSgAnalyzer) getProtocolAllRule(ruleObj *types.IpPermission, direction string) (
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
func (sga *AwsSgAnalyzer) getProtocolTCPUDPRule(ruleObj *types.IpPermission, direction string) (
	ruleStr string, ruleRes *commonvpc.SGRule, err error) {
	minPort := int64(*ruleObj.FromPort)
	maxPort := int64(*ruleObj.ToPort)
	dstPortMin := commonvpc.GetProperty(&minPort, connection.MinPort)
	dstPortMax := commonvpc.GetProperty(&maxPort, connection.MaxPort)
	dstPorts := fmt.Sprintf("%d-%d", dstPortMin, dstPortMax)
	connStr := fmt.Sprintf("protocol: %s,  dstPorts: %s", *ruleObj.IpProtocol, dstPorts)
	remote, err := sga.getRemoteCidr(ruleObj.IpRanges, ruleObj.UserIdGroupPairs)
	if err != nil {
		return "", nil, err
	}
	ruleRes = &commonvpc.SGRule{
		// TODO: src ports can be considered here?
		Connections: commonvpc.GetTCPUDPConns(*ruleObj.IpProtocol,
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

// getProtocolICMPRule returns rule results corresponding to the provided rule obj with icmp connection
func (sga *AwsSgAnalyzer) getProtocolICMPRule(ruleObj *types.IpPermission, direction string) (
	ruleStr string, ruleRes *commonvpc.SGRule, err error) {
	minPort := int64(*ruleObj.FromPort)
	maxPort := int64(*ruleObj.ToPort)
	conns := commonvpc.GetICMPconn(&minPort, &maxPort)
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

func (sga *AwsSgAnalyzer) GetSGRule(index int) (
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
		ruleStr, ruleRes, err = sga.getProtocolTCPUDPRule(&ruleObj, direction)
	case commonvpc.ProtocolUDP:
		ruleStr, ruleRes, err = sga.getProtocolTCPUDPRule(&ruleObj, direction)
	case commonvpc.ProtocolICMP:
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

func (sga *AwsSgAnalyzer) GetSGRules() (ingressRules, egressRules []*commonvpc.SGRule, err error) {
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

func (sga *AwsSgAnalyzer) SetSGmap(sgMap map[string]*commonvpc.SecurityGroup) {
	sga.sgMap = sgMap
}

func (sga *AwsSgAnalyzer) ReferencedIPblocks() []*ipblock.IPBlock {
	return sga.referencedIPblocks
}

func (sga *AwsSgAnalyzer) GetNumberOfRules() int {
	return len(sga.sgResource.IpPermissions) + len(sga.sgResource.IpPermissionsEgress)
}
