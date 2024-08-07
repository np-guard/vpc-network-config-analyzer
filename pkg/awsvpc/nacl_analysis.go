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

type AWSNACLAnalyzer struct {
	naclResource       *types.NetworkAcl
	referencedIPblocks []*ipblock.IPBlock
}

func NewAWSNACLAnalyzer(nacl *types.NetworkAcl) *AWSNACLAnalyzer {
	res := &AWSNACLAnalyzer{naclResource: nacl}
	return res
}

func (na *AWSNACLAnalyzer) GetNumberOfRules() int {
	return len(na.naclResource.Entries)
}

func (na *AWSNACLAnalyzer) Name() *string {
	return na.naclResource.NetworkAclId
}

func (na *AWSNACLAnalyzer) ReferencedIPblocks() []*ipblock.IPBlock {
	return na.referencedIPblocks
}

func (na *AWSNACLAnalyzer) GetNACLRule(index int) (ruleStr string, ruleRes *commonvpc.NACLRule, isIngress bool, err error) {
	var conns *connection.Set
	var connStr string
	ruleObj := na.naclResource.Entries[index]
	*ruleObj.Protocol = convertProtocol(*ruleObj.Protocol)
	switch *ruleObj.Protocol {
	case allProtocols:
		conns = connection.All()
		connStr = *ruleObj.Protocol
	case protocolTCP, protocolUDP:
		minPort := int64(*ruleObj.PortRange.From)
		maxPort := int64(*ruleObj.PortRange.To)
		conns = commonvpc.GetTCPUDPConns(*ruleObj.Protocol,
			connection.MinPort,
			connection.MaxPort,
			minPort,
			maxPort,
		)
		connStr = fmt.Sprintf("protocol: %s, dstPorts: %d-%d", *ruleObj.Protocol, minPort, maxPort)
	case protocolICMP:
		icmpType := int64(*ruleObj.IcmpTypeCode.Type)
		icmpCode := int64(*ruleObj.IcmpTypeCode.Code)
		conns = connection.ICMPConnection(icmpType, icmpType, icmpCode, icmpCode)
		connStr = fmt.Sprintf("protocol: %s", *ruleObj.Protocol)
	default:
		err = fmt.Errorf("GetNACLRule unsupported protocol type: %s ", *ruleObj.Protocol)
		return "", nil, false, err
	}
	action := string(ruleObj.RuleAction)
	ip, err := ipblock.FromCidr(*ruleObj.CidrBlock)
	if err != nil {
		return "", nil, false, err
	}
	ruleRes = &commonvpc.NACLRule{Src: ipblock.GetCidrAll(), Dst: ip, Connections: conns, Action: action}
	isIngress = !*ruleObj.Egress
	direction := commonvpc.Outbound
	if isIngress {
		direction = commonvpc.Inbound
	}
	ruleStr = fmt.Sprintf("index: %d, direction: %s ,cidr: %s, conn: %s, action: %s\n",
		index, direction, ip, connStr, action)
	return ruleStr, ruleRes, isIngress, nil
}

func (na *AWSNACLAnalyzer) GetNACLRules() (ingressRules, egressRules []*commonvpc.NACLRule, err error) {
	ingressRules = []*commonvpc.NACLRule{}
	egressRules = []*commonvpc.NACLRule{}
	for index := range na.naclResource.Entries {
		_, ruleObj, isIngress, err := na.GetNACLRule(index)
		if err != nil {
			return nil, nil, err
		}
		if ruleObj == nil {
			continue
		}
		na.referencedIPblocks = append(na.referencedIPblocks, ruleObj.Src.Split()...)
		na.referencedIPblocks = append(na.referencedIPblocks, ruleObj.Dst.Split()...)
		ruleObj.Index = index
		if isIngress {
			ingressRules = append(ingressRules, ruleObj)
		} else {
			egressRules = append(egressRules, ruleObj)
		}
	}
	return ingressRules, egressRules, nil
}
