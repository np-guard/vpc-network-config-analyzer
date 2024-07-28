/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
)

const (
	ALLOW string = "allow"
	DENY  string = "deny"
)

type IBMNACLAnalyzer struct {
	naclResource       *vpc1.NetworkACL
	referencedIPblocks []*ipblock.IPBlock
}

func NewIBMNACLAnalyzer(nacl *vpc1.NetworkACL) *IBMNACLAnalyzer {
	res := &IBMNACLAnalyzer{naclResource: nacl}
	return res
}

func getPortsStr(minPort, maxPort int64) string {
	return fmt.Sprintf("%d-%d", minPort, maxPort)
}

func (na *IBMNACLAnalyzer) GetNumberOfRules() int {
	return len(na.naclResource.Rules)
}

func (na *IBMNACLAnalyzer) Name() *string {
	return na.naclResource.Name
}

func (na *IBMNACLAnalyzer) ReferencedIPblocks() []*ipblock.IPBlock {
	return na.referencedIPblocks
}

func (na *IBMNACLAnalyzer) GetNACLRule(index int) (ruleStr string, ruleRes *commonvpc.NACLRule, isIngress bool, err error) {
	var conns *connection.Set
	var direction, src, dst, action string
	var connStr string
	rule := na.naclResource.Rules[index]
	switch ruleObj := rule.(type) {
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolAll:
		conns = connection.All()
		connStr = *ruleObj.Protocol
		direction = *ruleObj.Direction
		src = *ruleObj.Source
		dst = *ruleObj.Destination
		action = *ruleObj.Action
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolTcpudp:
		conns = commonvpc.GetTCPUDPConns(*ruleObj.Protocol,
			commonvpc.GetProperty(ruleObj.SourcePortMin, connection.MinPort),
			commonvpc.GetProperty(ruleObj.SourcePortMax, connection.MaxPort),
			commonvpc.GetProperty(ruleObj.DestinationPortMin, connection.MinPort),
			commonvpc.GetProperty(ruleObj.DestinationPortMax, connection.MaxPort),
		)
		srcPorts := getPortsStr(*ruleObj.SourcePortMin, *ruleObj.SourcePortMax)
		dstPorts := getPortsStr(*ruleObj.DestinationPortMin, *ruleObj.DestinationPortMax)
		connStr = fmt.Sprintf("protocol: %s, srcPorts: %s, dstPorts: %s", *ruleObj.Protocol, srcPorts, dstPorts)
		direction = *ruleObj.Direction
		src = *ruleObj.Source
		dst = *ruleObj.Destination
		action = *ruleObj.Action
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolIcmp:
		conns = commonvpc.GetICMPconn(ruleObj.Type, ruleObj.Code)
		connStr = fmt.Sprintf("protocol: %s", *ruleObj.Protocol)
		direction = *ruleObj.Direction
		src = *ruleObj.Source
		dst = *ruleObj.Destination
		action = *ruleObj.Action
	default:
		err = fmt.Errorf("GetNACLRule unsupported type for rule: %s ", rule)
		return "", nil, false, err
	}

	srcIP, dstIP, err := ipblock.PairCIDRsToIPBlocks(src, dst)
	if err != nil {
		return "", nil, false, err
	}
	ruleRes = &commonvpc.NACLRule{Src: srcIP, Dst: dstIP, Connections: conns, Action: action}
	isIngress = direction == commonvpc.Inbound
	ruleStr = fmt.Sprintf("index: %d, direction: %s , src: %s , dst: %s, conn: %s, action: %s\n",
		index, direction, src, dst, connStr, action)
	return ruleStr, ruleRes, isIngress, nil
}

func (na *IBMNACLAnalyzer) GetNACLRules() (ingressRules, egressRules []*commonvpc.NACLRule, err error) {
	ingressRules = []*commonvpc.NACLRule{}
	egressRules = []*commonvpc.NACLRule{}
	for index := range na.naclResource.Rules {
		rule := na.naclResource.Rules[index]
		_, ruleObj, isIngress, err := na.GetNACLRule(index)
		if err != nil {
			return nil, nil, err
		}
		if rule == nil {
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
