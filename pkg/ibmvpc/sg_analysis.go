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
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
)

// IBMSGAnalyzer implements commonvpc.SpecificSGAnalyzer
type IBMSGAnalyzer struct {
	SgResource         *vpc1.SecurityGroup
	sgMap              map[string]*commonvpc.SecurityGroup
	referencedIPblocks []*netset.IPBlock
}

func NewIBMSGAnalyzer(sg *vpc1.SecurityGroup) *IBMSGAnalyzer {
	res := &IBMSGAnalyzer{SgResource: sg}
	return res
}

func isIngressRule(direction *string) bool {
	if direction == nil {
		return false
	}
	if *direction == "inbound" {
		return true
	}
	return false
}

func (sga *IBMSGAnalyzer) Name() *string {
	return sga.SgResource.Name
}

// getRemoteCidr gets remote rule object interface and returns it's IPBlock
func (sga *IBMSGAnalyzer) getRemoteCidr(remote vpc1.SecurityGroupRuleRemoteIntf) (target *netset.IPBlock,
	cidrRes string, remoteSGName string, err error) {
	// TODO: on actual run from SG example, the type of remoteObj is SecurityGroupRuleRemote and not SecurityGroupRuleRemoteCIDR,
	// even if cidr is defined
	//TODO: handle other remote types:
	// SecurityGroupRuleRemoteIP
	// SecurityGroupRuleRemoteSecurityGroupReference

	// how can infer type of remote from this object?
	// can also be Address or CRN or ...
	if remoteObj, ok := remote.(*vpc1.SecurityGroupRuleRemote); ok {
		target, cidrRes, err = commonvpc.GetIPBlockResult(remoteObj.CIDRBlock,
			remoteObj.Address, remoteObj.Name, sga.sgMap)
		if err != nil {
			return nil, "", "", err
		}
		if remoteObj.Name != nil {
			remoteSGName = *remoteObj.Name
		}
	}

	if !target.IsEmpty() {
		sga.referencedIPblocks = append(sga.referencedIPblocks, target.Split()...)
	}
	return target, cidrRes, remoteSGName, nil
}

func getDefaultLocal() (ipb *netset.IPBlock, cidr string) {
	return netset.GetCidrAll(), netset.CidrAll
}

// getRemoteCidr gets local rule object interface and returns it's IPBlock
func (sga *IBMSGAnalyzer) getLocalCidr(local vpc1.SecurityGroupRuleLocalIntf) (*netset.IPBlock, string, error) {
	var localIP *netset.IPBlock
	var cidrRes string
	var err error
	if localObj, ok := local.(*vpc1.SecurityGroupRuleLocal); ok {
		localIP, cidrRes, err = commonvpc.GetIPBlockResult(localObj.CIDRBlock, localObj.Address, nil, sga.sgMap)
		if err != nil {
			return nil, "", err
		}

		if localIP == nil || cidrRes == "" {
			// support old config files with missing local field
			localIP, cidrRes = getDefaultLocal()
		}
	}
	if localIP == nil || cidrRes == "" {
		// support old config files with missing local field
		localIP, cidrRes = getDefaultLocal()
	}
	return localIP, cidrRes, nil
}

func (sga *IBMSGAnalyzer) getProtocolAllRule(ruleObj *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolAll) (
	ruleStr string, ruleRes *commonvpc.SGRule, isIngress bool, err error) {
	ruleRes = &commonvpc.SGRule{}
	direction := *ruleObj.Direction
	isIngress = isIngressRule(ruleObj.Direction)
	protocol := *ruleObj.Protocol
	remoteCidr, localCidr, remoteSGName := "", "", ""
	var remote, local *netset.IPBlock
	remote, remoteCidr, remoteSGName, err = sga.getRemoteCidr(ruleObj.Remote)
	if err != nil {
		return "", nil, false, err
	}
	local, localCidr, err = sga.getLocalCidr(ruleObj.Local)
	if err != nil {
		return "", nil, false, err
	}
	connStr := fmt.Sprintf("protocol: %s", protocol)
	ruleStr = getRuleStr(direction, *ruleObj.ID, connStr, remoteCidr, remoteSGName, localCidr)
	ruleRes.Remote = commonvpc.NewRuleTarget(remote, remoteSGName)
	ruleRes.Local = local
	ruleRes.Connections = netset.AllTransports()
	return ruleStr, ruleRes, isIngress, nil
}

func (sga *IBMSGAnalyzer) getProtocolTCPUDPRule(ruleObj *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp) (
	ruleStr string, ruleRes *commonvpc.SGRule, isIngress bool, err error) {
	direction := *ruleObj.Direction
	isIngress = isIngressRule(ruleObj.Direction)
	remote, remoteCidr, remoteSGName, err := sga.getRemoteCidr(ruleObj.Remote)
	if err != nil {
		return "", nil, false, err
	}
	local, localCidr, err := sga.getLocalCidr(ruleObj.Local)
	if err != nil {
		return "", nil, false, err
	}
	dstPortMin := commonvpc.GetProperty(ruleObj.PortMin, netp.MinPort)
	dstPortMax := commonvpc.GetProperty(ruleObj.PortMax, netp.MaxPort)
	dstPorts := fmt.Sprintf("%d-%d", dstPortMin, dstPortMax)
	connStr := fmt.Sprintf("protocol: %s,  dstPorts: %s", *ruleObj.Protocol, dstPorts)
	ruleStr = getRuleStr(direction, *ruleObj.ID, connStr, remoteCidr, remoteSGName, localCidr)
	ruleRes = &commonvpc.SGRule{
		// TODO: src ports can be considered here?
		Connections: commonvpc.GetTCPUDPConns(*ruleObj.Protocol,
			netp.MinPort,
			netp.MaxPort,
			dstPortMin,
			dstPortMax,
		),
		Remote: commonvpc.NewRuleTarget(remote, remoteSGName),
		Local:  local,
	}
	return ruleStr, ruleRes, isIngress, nil
}

func getRuleStr(direction, id, connStr, remoteCidr, remoteSGName, localCidr string) string {
	remoteSGStr := remoteCidr
	if remoteSGName != "" {
		remoteSGStr = remoteSGName + " (" + remoteCidr + ")"
	}
	return fmt.Sprintf("id: %s, direction: %s, local: %s, remote: %s, %s\n",
		id, direction, localCidr, remoteSGStr, connStr)
}

func (sga *IBMSGAnalyzer) getProtocolICMPRule(ruleObj *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp) (
	ruleStr string, ruleRes *commonvpc.SGRule, isIngress bool, err error) {
	remote, remoteCidr, remoteSGName, err := sga.getRemoteCidr(ruleObj.Remote)
	if err != nil {
		return
	}
	local, localCidr, err := sga.getLocalCidr(ruleObj.Local)
	if err != nil {
		return
	}
	conns := commonvpc.GetICMPconn(ruleObj.Type, ruleObj.Code)
	ruleStr = getRuleStr(*ruleObj.Direction, *ruleObj.ID, common.LongString(conns), remoteCidr, remoteSGName, localCidr)
	ruleRes = &commonvpc.SGRule{
		Connections: conns,
		Remote:      commonvpc.NewRuleTarget(remote, remoteSGName),
		Local:       local,
	}
	isIngress = isIngressRule(ruleObj.Direction)
	return
}

// GetSGRule gets index of the rule and returns the rule results line and obj
func (sga *IBMSGAnalyzer) GetSGRule(index int) (
	ruleStr string, ruleRes *commonvpc.SGRule, isIngress bool, err error) {
	rule := sga.SgResource.Rules[index]
	switch ruleObj := rule.(type) {
	case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolAll:
		ruleStr, ruleRes, isIngress, err = sga.getProtocolAllRule(ruleObj)
	case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp:
		ruleStr, ruleRes, isIngress, err = sga.getProtocolTCPUDPRule(ruleObj)
	case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp:
		ruleStr, ruleRes, isIngress, err = sga.getProtocolICMPRule(ruleObj)
	default:
		return "", nil, false, fmt.Errorf("getSGRule error: unsupported type")
	}
	if err != nil {
		return "", nil, false, err
	}
	ruleRes.Index = index
	return ruleStr, ruleRes, isIngress, nil
}

// GetSGRules returns ingress and egress rule objects
func (sga *IBMSGAnalyzer) GetSGRules() (ingressRules, egressRules []*commonvpc.SGRule, err error) {
	return commonvpc.GetSGRules(sga)
}

// ReferencedIPblocks returns referencedIPblocks filed
func (sga *IBMSGAnalyzer) ReferencedIPblocks() []*netset.IPBlock {
	return sga.referencedIPblocks
}

// SetSGmap gets sgMap (a map from sg name to SecurityGroup obj) and save it in IBMSGAnalyzer
func (sga *IBMSGAnalyzer) SetSGmap(sgMap map[string]*commonvpc.SecurityGroup) {
	sga.sgMap = sgMap
}

// GetNumberOfRules returns number of egress and ingress rules of the securityGroup obj in IBMSGAnalyzer
func (sga *IBMSGAnalyzer) GetNumberOfRules() int {
	return len(sga.SgResource.Rules)
}
