/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"fmt"
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
)

// AWSNACLAnalyzer implements commonvpc.SpecificNACLAnalyzer
type AWSNACLAnalyzer struct {
	naclResource       *types.NetworkAcl
	referencedIPblocks []*ipblock.IPBlock
	// all over the analyzer code, we assume that the acl rules are ordered by their priority.
	// however, in aws, the priority is being config by the rule number, and the order has no meaning.
	// so prioritiesEntries are the entries as in naclResource.Entries, sorted by the rule number:
	prioritiesEntries []types.NetworkAclEntry
}

func NewAWSNACLAnalyzer(nacl *types.NetworkAcl) *AWSNACLAnalyzer {
	prioritiesEntries := slices.Clone(nacl.Entries)
	slices.SortFunc(prioritiesEntries, func(a, b types.NetworkAclEntry) int { return int(*a.RuleNumber) - int(*b.RuleNumber) })
	return &AWSNACLAnalyzer{naclResource: nacl, prioritiesEntries: prioritiesEntries}
}

// return number of ingress and egress rules
func (na *AWSNACLAnalyzer) GetNumberOfRules() int {
	return len(na.prioritiesEntries)
}

func (na *AWSNACLAnalyzer) Name() *string {
	return getResourceName(na.naclResource.Tags, na.naclResource.NetworkAclId)
}

func (na *AWSNACLAnalyzer) ReferencedIPblocks() []*ipblock.IPBlock {
	return na.referencedIPblocks
}

// SetReferencedIPblocks updates referenced ip blocks
func (na *AWSNACLAnalyzer) SetReferencedIPblocks(referencedIPblocks []*ipblock.IPBlock) {
	na.referencedIPblocks = referencedIPblocks
}

// GetNACLRule gets index of the rule and returns the rule results line and obj
func (na *AWSNACLAnalyzer) GetNACLRule(index int) (ruleStr string, ruleRes *commonvpc.NACLRule, isIngress bool, err error) {
	var conns *connection.Set
	var connStr string
	ruleObj := na.prioritiesEntries[index]
	protocol := convertProtocol(*ruleObj.Protocol)
	ruleNumber := *ruleObj.RuleNumber
	switch protocol {
	case allProtocols:
		conns = connection.All()
		connStr = protocol
	case protocolTCP, protocolUDP:
		minPort := int64(*ruleObj.PortRange.From)
		maxPort := int64(*ruleObj.PortRange.To)
		conns = commonvpc.GetTCPUDPConns(protocol,
			connection.MinPort,
			connection.MaxPort,
			minPort,
			maxPort,
		)
		connStr = fmt.Sprintf("protocol: %s, dstPorts: %d-%d", protocol, minPort, maxPort)
	case protocolICMP:
		icmpTypeMin, icmpTypeMax, icmpCodeMin, icmpCodeMax,
			err := handleIcmpTypeCode(ruleObj.IcmpTypeCode.Type, ruleObj.IcmpTypeCode.Code)

		if err != nil {
			return "", nil, false, err
		}
		conns = connection.ICMPConnection(icmpTypeMin, icmpTypeMax, icmpCodeMin, icmpCodeMax)
		connStr = fmt.Sprintf("protocol: %s", protocol)
	default:
		err = fmt.Errorf("GetNACLRule unsupported protocol type: %s ", *ruleObj.Protocol)
		return "", nil, false, err
	}
	action := string(ruleObj.RuleAction)
	ip, err := ipblock.FromCidr(*ruleObj.CidrBlock)
	if err != nil {
		return "", nil, false, err
	}
	isIngress = !*ruleObj.Egress
	src, dst := ipblock.GetCidrAll(), ip
	direction := commonvpc.Outbound
	if isIngress {
		src, dst = dst, src
		direction = commonvpc.Inbound
	}
	ruleRes = &commonvpc.NACLRule{Src: src, Dst: dst, Connections: conns, Action: action}
	ruleStr = fmt.Sprintf("ruleNumber: %d, direction: %s ,cidr: %s, action: %s, conn: %s\n",
		ruleNumber, direction, ip, action, connStr)
	return ruleStr, ruleRes, isIngress, nil
}

// GetNACLRules returns ingress and egress rule objects
func (na *AWSNACLAnalyzer) GetNACLRules() (ingressRules, egressRules []*commonvpc.NACLRule, err error) {
	return commonvpc.GetNACLRules(na)
}
