/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
)

// IBMNACLAnalyzer implements commonvpc.SpecificNACLAnalyzer
type IBMNACLAnalyzer struct {
	naclResource       *vpc1.NetworkACL
	referencedIPblocks []*netset.IPBlock
}

func NewIBMNACLAnalyzer(nacl *vpc1.NetworkACL) *IBMNACLAnalyzer {
	return &IBMNACLAnalyzer{naclResource: nacl}
}

func getPortsStr(minPort, maxPort int64) string {
	return fmt.Sprintf("%d-%d", minPort, maxPort)
}

// return number of ingress and egress rules
func (na *IBMNACLAnalyzer) GetNumberOfRules() int {
	return len(na.naclResource.Rules)
}

func (na *IBMNACLAnalyzer) Name() *string {
	return na.naclResource.Name
}

func (na *IBMNACLAnalyzer) ReferencedIPblocks() []*netset.IPBlock {
	return na.referencedIPblocks
}

// SetReferencedIPblocks updates referenced ip blocks
func (na *IBMNACLAnalyzer) SetReferencedIPblocks(referencedIPblocks []*netset.IPBlock) {
	na.referencedIPblocks = referencedIPblocks
}

// GetNACLRule gets index of the rule and returns the rule results line and obj
func (na *IBMNACLAnalyzer) GetNACLRule(index int) (ruleStr string, ruleRes *commonvpc.NACLRule, isIngress bool, err error) {
	var conns *netset.TransportSet
	var direction, src, dst, action string
	var name, connStr string
	rule := na.naclResource.Rules[index]
	var protocol, portsStr string
	switch ruleObj := rule.(type) {
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolAll:
		name = *ruleObj.Name
		conns = netset.AllTransports()
		protocol = *ruleObj.Protocol
		direction = *ruleObj.Direction
		src = *ruleObj.Source
		dst = *ruleObj.Destination
		action = *ruleObj.Action
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolTcpudp:
		name = *ruleObj.Name
		conns = commonvpc.GetTCPUDPConns(*ruleObj.Protocol,
			commonvpc.GetProperty(ruleObj.SourcePortMin, netp.MinPort),
			commonvpc.GetProperty(ruleObj.SourcePortMax, netp.MaxPort),
			commonvpc.GetProperty(ruleObj.DestinationPortMin, netp.MinPort),
			commonvpc.GetProperty(ruleObj.DestinationPortMax, netp.MaxPort),
		)
		srcPorts := getPortsStr(*ruleObj.SourcePortMin, *ruleObj.SourcePortMax)
		dstPorts := getPortsStr(*ruleObj.DestinationPortMin, *ruleObj.DestinationPortMax)
		protocol = *ruleObj.Protocol
		portsStr = fmt.Sprintf(", srcPorts: %s, dstPorts: %s", srcPorts, dstPorts)
		direction = *ruleObj.Direction
		src = *ruleObj.Source
		dst = *ruleObj.Destination
		action = *ruleObj.Action
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolIcmp:
		name = *ruleObj.Name
		conns = commonvpc.GetICMPconn(ruleObj.Type, ruleObj.Code)
		protocol = *ruleObj.Protocol
		direction = *ruleObj.Direction
		src = *ruleObj.Source
		dst = *ruleObj.Destination
		action = *ruleObj.Action
		if ruleObj.Type != nil {
			portsStr = fmt.Sprintf(", type: %d", *ruleObj.Type)
		}
		if ruleObj.Code != nil {
			portsStr += fmt.Sprintf(", code: %d", *ruleObj.Code)
		}
	default:
		err = fmt.Errorf("GetNACLRule unsupported type for rule: %s ", rule)
		return "", nil, false, err
	}
	connStr = "protocol: " + protocol + portsStr

	srcIP, dstIP, err := netset.PairCIDRsToIPBlocks(src, dst)
	if err != nil {
		return "", nil, false, err
	}
	ruleRes = &commonvpc.NACLRule{Src: srcIP, Dst: dstIP, Connections: conns, Action: action}
	isIngress = direction == commonvpc.Inbound
	priority := na.getNACLRulePriority(direction, index)
	ruleStr = fmt.Sprintf("name: %s, priority: %d, action: %s, direction: %s, source: %s, destination: %s,"+
		" %s\n", name, priority, action, direction, src, dst, connStr)
	return ruleStr, ruleRes, isIngress, nil
}

// getNACLRulePriority computes the priority of a rule
// priorities starts with 1 and are calculated separately for ingress and egress
func (na *IBMNACLAnalyzer) getNACLRulePriority(myDirection string, myIndex int) int {
	priority := 1
	for index := 0; index < myIndex; index++ {
		rule := na.naclResource.Rules[index]
		var direction string
		switch ruleObj := rule.(type) {
		case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolAll:
			direction = *ruleObj.Direction
		case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolTcpudp:
			direction = *ruleObj.Direction
		case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolIcmp:
			direction = *ruleObj.Direction
		default:
			return -1 // if Rule not a legal object, GetNACLRule will dump in initialization
		}
		if myDirection == direction {
			priority++
		}
	}
	return priority
}

// GetNACLRules returns ingress and egress rule objects
func (na *IBMNACLAnalyzer) GetNACLRules() (ingressRules, egressRules []*commonvpc.NACLRule, err error) {
	return commonvpc.GetNACLRules(na)
}
