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
	ALLOW string = "allow"
	DENY  string = "deny"
)

type IBMNACLAnalyzer struct {
	naclResource       *types.NetworkAcl
	referencedIPblocks []*ipblock.IPBlock
}

func NewIBMNACLAnalyzer(nacl *types.NetworkAcl) *IBMNACLAnalyzer {
	res := &IBMNACLAnalyzer{naclResource: nacl}
	return res
}

func getPortsStr(minPort, maxPort int64) string {
	return fmt.Sprintf("%d-%d", minPort, maxPort)
}

func (na *IBMNACLAnalyzer) GetNumberOfRules() int {
	return len(na.naclResource.Entries)
}

func (na *IBMNACLAnalyzer) Name() *string {
	return na.naclResource.NetworkAclId
}

func (na *IBMNACLAnalyzer) ReferencedIPblocks() []*ipblock.IPBlock {
	return na.referencedIPblocks
}

func (na *IBMNACLAnalyzer) GetNACLRule(index int) (ruleStr string, ruleRes *commonvpc.NACLRule, isIngress bool, err error) {
	var conns *connection.Set
	var action, direction string
	var connStr string
	ruleObj := na.naclResource.Entries[index]
	switch *ruleObj.Protocol {
	case "-1":
		conns = connection.All()
		connStr = *ruleObj.Protocol
	case protocolTCP, protocolUDP:
		minPort := int64(*ruleObj.PortRange.From)
		maxPort := int64(*ruleObj.PortRange.To)
		dstPortMin := commonvpc.GetProperty(&minPort, connection.MinPort)
		dstPortMax := commonvpc.GetProperty(&maxPort, connection.MaxPort)
		conns = commonvpc.GetTCPUDPConns(*ruleObj.Protocol,
			connection.MinPort,
			connection.MaxPort,
			dstPortMin,
			dstPortMax,
		)
		dstPorts := getPortsStr(dstPortMin, dstPortMax)
		connStr = fmt.Sprintf("protocol: %s, dstPorts: %s", *ruleObj.Protocol, dstPorts)
	case protocolICMP:
		icmpType := int64(*ruleObj.IcmpTypeCode.Type)
		icmpCode := int64(*ruleObj.IcmpTypeCode.Code)
		conns = commonvpc.GetICMPconn(&icmpType, &icmpCode)
		connStr = fmt.Sprintf("protocol: %s", *ruleObj.Protocol)
	default:
		err = fmt.Errorf("GetNACLRule unsupported protocol type: %s ", *ruleObj.Protocol)
		return "", nil, false, err
	}
	action = string(ruleObj.RuleAction)
	ip, err := ipblock.FromCidr(*ruleObj.CidrBlock)
	if err != nil {
		return "", nil, false, err
	}
	ruleRes = &commonvpc.NACLRule{Src: ipblock.GetCidrAll(), Dst: ip, Connections: conns, Action: action}
	isIngress = !*ruleObj.Egress
	direction = commonvpc.Outbound
	if isIngress {
		direction = commonvpc.Inbound
	}
	ruleStr = fmt.Sprintf("index: %d, direction: %s ,cidr: %s, conn: %s, action: %s\n",
		index, direction, ip, connStr, action)
	return ruleStr, ruleRes, isIngress, nil
}

func (na *IBMNACLAnalyzer) GetNACLRules() (ingressRules, egressRules []*commonvpc.NACLRule, err error) {
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
