/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const blockedTCPResponse = "blocked-TCP-response"
const blockedTCPResponseDescription = "Blocked TCP response"
const deliminator = "/"

// overlapSubnets: overlapping subnet ranges (relevant mostly for the multiple VPCs use case)
type blockedTCPResponseLint struct {
	connectionLinter
}

func newBlockedTCPResponseLint(configs map[string]*vpcmodel.VPCConfig,
	nodesConn map[string]*vpcmodel.VPCConnectivity) *blockedTCPResponseLint {
	return &blockedTCPResponseLint{
		connectionLinter{
			basicLinter{
				configs:     configs,
				name:        blockedTCPResponse,
				description: blockedTCPResponseDescription,
			},
			nodesConn}}
}

// TCP connection with no response
type blockedTCPResponseConn struct {
	src           vpcmodel.EndpointElem
	dst           vpcmodel.EndpointElem
	tcpRspDisable *connection.Set
}

// /////////////////////////////////////////////////////////
// lint interface implementation for overlapSubnets
// ////////////////////////////////////////////////////////
func (lint *blockedTCPResponseLint) check() error {
	for _, nodesConn := range lint.nodesConn {
		for _, line := range nodesConn.GroupedConnectivity.GroupedLines {
			tcpRspDisable := line.CommonProperties.Conn.TCPRspDisable
			if !tcpRspDisable.IsEmpty() {
				lint.addFinding(&blockedTCPResponseConn{src: line.Src, dst: line.Dst, tcpRspDisable: tcpRspDisable})
			}
		}
	}
	return nil
}

///////////////////////////////////////////////////////////
// finding interface implementation for overlapSubnets
//////////////////////////////////////////////////////////

func (finding *blockedTCPResponseConn) vpc() []vpcmodel.VPCResourceIntf {
	return []vpcmodel.VPCResourceIntf{getVPCFromEndpointElem(finding.src), getVPCFromEndpointElem(finding.dst)}
}

func getVPCFromEndpointElem(ep vpcmodel.EndpointElem) vpcmodel.VPCResourceIntf {
	if vpcResource, ok := ep.(vpcmodel.VPCResourceIntf); ok {
		return vpcResource.VPC()
	}
	// should never get here; thus not returning an error
	return nil
}

func (finding *blockedTCPResponseConn) string() string {
	vpcSrcName := finding.getVpcName(0)
	vpcDstName := finding.getVpcName(1)
	srcToDstStr := fmt.Sprintf("from %v%s to %v%s",
		vpcSrcName, finding.src.Name(), vpcDstName, finding.dst.Name())

	return fmt.Sprintf("In the connection %s %s response is blocked", srcToDstStr,
		strings.ReplaceAll(finding.tcpRspDisable.String(), "protocol: ", ""))
}

func (finding *blockedTCPResponseConn) getVpcName(i int) string {
	if finding.vpc()[i] != nil { // nil if external address
		return finding.vpc()[i].Name() + deliminator
	}
	return ""
}

// TCP connection with no response
type blockedTCPResponseConnJSON struct {
	Src           string             `json:"source"`
	Dst           string             `json:"destination"`
	TCPRspDisable connection.Details `json:"tcp_non_responsive"`
}

func (finding *blockedTCPResponseConn) toJSON() any {
	vpcSrcName := finding.vpc()[0].Name()
	vpcDstName := finding.vpc()[1].Name()
	res := blockedTCPResponseConnJSON{Src: vpcSrcName + deliminator + finding.src.Name(),
		Dst: vpcDstName + deliminator + finding.dst.Name(), TCPRspDisable: connection.ToJSON(finding.tcpRspDisable)}
	return res
}
