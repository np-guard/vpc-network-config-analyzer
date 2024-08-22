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
	allProtocols = "all"
	protocolUDP  = "udp"
	protocolICMP = "icmp"
)

// AWSSGAnalyzer implements commonvpc.SpecificSGAnalyzer
type AWSSGAnalyzer struct {
	sgResource         *types.SecurityGroup
	referencedIPblocks []*ipblock.IPBlock
	sgMap              map[string]*commonvpc.SecurityGroup
}

func NewAWSSGAnalyzer(sg *types.SecurityGroup) *AWSSGAnalyzer {
	res := &AWSSGAnalyzer{sgResource: sg}
	return res
}

func getSGName(sg *types.SecurityGroup) *string {
	if sg.GroupName != nil && *sg.GroupName != "" {
		return sg.GroupName
	}
	return getResourceName(sg.Tags, sg.GroupId)
}

func (sga *AWSSGAnalyzer) Name() *string {
	return getSGName(sga.sgResource)
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
func (sga *AWSSGAnalyzer) getProtocolTCPUDPRule(ruleObj *types.IpPermission, direction, protocol string) (
	ruleStr string, ruleRes *commonvpc.SGRule, err error) {
	minPort := int64(*ruleObj.FromPort)
	maxPort := int64(*ruleObj.ToPort)
	connStr := fmt.Sprintf("protocol: %s, dstPorts: %d-%d", protocol, minPort, maxPort)
	remote, err := sga.getRemoteCidr(ruleObj.IpRanges, ruleObj.UserIdGroupPairs)
	if err != nil {
		return "", nil, err
	}
	ruleRes = &commonvpc.SGRule{
		// TODO: src ports can be considered here?
		Connections: commonvpc.GetTCPUDPConns(protocol,
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
	return fmt.Sprintf("direction: %s, target: %s, conns: %s\n", direction, ipRanges, connStr)
}

func handleIcmpTypeCode(icmpType, icmpCode *int32) (newIcmpTypeMin, newIcmpTypeMax,
	newIcmpCodeMin, newIcmpCodeMax int64, err error) {
	if icmpCode == nil || icmpType == nil {
		return 0, 0, 0, 0, fmt.Errorf("unexpected nil icmp type or code")
	}
	newIcmpTypeMin = int64(*icmpType)
	newIcmpCodeMin = int64(*icmpCode)
	newIcmpTypeMax = int64(*icmpType)
	newIcmpCodeMax = int64(*icmpCode)

	if newIcmpCodeMin == -1 {
		newIcmpCodeMin = connection.MinICMPCode
		newIcmpCodeMax = connection.MaxICMPCode
	}
	if newIcmpTypeMin == -1 {
		newIcmpTypeMin = connection.MinICMPType
		newIcmpTypeMax = connection.MaxICMPType
	}

	return
}

// getProtocolICMPRule returns rule results corresponding to the provided rule obj with icmp connection
func (sga *AWSSGAnalyzer) getProtocolICMPRule(ruleObj *types.IpPermission, direction string) (
	ruleStr string, ruleRes *commonvpc.SGRule, err error) {
	icmpTypeMin, icmpTypeMax, icmpCodeMin, icmpCodeMax,
		err := handleIcmpTypeCode(ruleObj.FromPort, ruleObj.ToPort)

	if err != nil {
		return "", nil, err
	}
	conns := connection.ICMPConnection(icmpTypeMin, icmpTypeMax, icmpCodeMin, icmpCodeMax)
	connStr := fmt.Sprintf("protocol: %s, icmpType: %s", *ruleObj.IpProtocol, conns)
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
	case "-1", allProtocols:
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

// GetSGRule gets index of the rule and returns the rule results line and obj
func (sga *AWSSGAnalyzer) GetSGRule(index int) (
	ruleStr string, ruleRes *commonvpc.SGRule, isIngress bool, err error) {
	var ruleObj types.IpPermission
	direction := commonvpc.Inbound
	listIndex := index
	if index < len(sga.sgResource.IpPermissions) {
		isIngress = true
		ruleObj = sga.sgResource.IpPermissions[listIndex]
	} else {
		direction = commonvpc.Outbound
		isIngress = false
		listIndex = index - len(sga.sgResource.IpPermissions)
		ruleObj = sga.sgResource.IpPermissionsEgress[listIndex]
	}
	protocol := convertProtocol(*ruleObj.IpProtocol)
	switch protocol {
	case allProtocols: // all protocols
		ruleStr, ruleRes, err = sga.getProtocolAllRule(&ruleObj, direction)
	case protocolTCP, protocolUDP:
		ruleStr, ruleRes, err = sga.getProtocolTCPUDPRule(&ruleObj, direction, protocol)
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
	tableName := "IpPermissions's"
	if !isIngress {
		tableName = "IpPermissionsEgress's"
	}
	return fmt.Sprintf("%s index: %d, %v", tableName, listIndex, ruleStr), ruleRes, isIngress, nil
}

// GetSGRules returns ingress and egress rule objects
func (sga *AWSSGAnalyzer) GetSGRules() (ingressRules, egressRules []*commonvpc.SGRule, err error) {
	return commonvpc.GetSGRules(sga)
}

// SetSGmap gets sgMap (a map from sg groupID to SecurityGroup obj) and save it in AWSSGAnalyzer
func (sga *AWSSGAnalyzer) SetSGmap(sgMap map[string]*commonvpc.SecurityGroup) {
	sga.sgMap = sgMap
}

// ReferencedIPblocks returns referencedIPblocks filed
func (sga *AWSSGAnalyzer) ReferencedIPblocks() []*ipblock.IPBlock {
	return sga.referencedIPblocks
}

// GetNumberOfRules returns number of egress and ingress rules of the securityGroup obj in AWSSGAnalyzer
func (sga *AWSSGAnalyzer) GetNumberOfRules() int {
	return len(sga.sgResource.IpPermissions) + len(sga.sgResource.IpPermissionsEgress)
}
