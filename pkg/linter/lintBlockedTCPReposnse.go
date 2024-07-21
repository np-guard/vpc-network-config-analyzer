/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"
	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const blockedTCPResponse = "blocked-TCP-response"
const deliminator = "/"

// overlapSubnets: overlapping subnet ranges (relevant mostly for the multiple VPCs use case)
type blockedTCPResponseLint struct {
	connectionLinter
}

// TCP connection with no response
type blockedTCPResponseConn struct {
	Src           vpcmodel.EndpointElem `json:"source"`
	Dst           vpcmodel.EndpointElem `json:"destination"`
	TCPRspDisable *connection.Set       `json:"tcp-non-responsive"`
}

// /////////////////////////////////////////////////////////
// lint interface implementation for overlapSubnets
// ////////////////////////////////////////////////////////
func (lint *blockedTCPResponseLint) lintName() string {
	return blockedTCPResponse
}

func (lint *blockedTCPResponseLint) lintDescription() string {
	return "TCP Connections for which response is disabled"
}

func (lint *blockedTCPResponseLint) check() error {
	for _, nodesConn := range lint.nodesConn {
		for _, line := range nodesConn.GroupedConnectivity.GroupedLines {
			tcpRspDisable := line.CommonProperties.Conn.TCPRspDisable
			if !tcpRspDisable.IsEmpty() {
				lint.addFinding(&blockedTCPResponseConn{Src: line.Src, Dst: line.Dst, TCPRspDisable: tcpRspDisable})
			}
		}
	}
	return nil
}

///////////////////////////////////////////////////////////
// finding interface implementation for overlapSubnets
//////////////////////////////////////////////////////////

func (finding *blockedTCPResponseConn) vpc() []string {
	return []string{getVPCFromEndpointElem(finding.Src).Name(), getVPCFromEndpointElem(finding.Dst).Name()}
}

func getVPCFromEndpointElem(ep vpcmodel.EndpointElem) vpcmodel.VPCResourceIntf {
	if vpcResource, ok := ep.(vpcmodel.VPCResourceIntf); ok {
		return vpcResource.VPC()
	}
	// should never get here; thus not returning an error
	return nil
}

func (finding *blockedTCPResponseConn) string() string {
	vpcSrc := finding.vpc()[0]
	vpcDst := finding.vpc()[1]
	srcToDstStr := ""
	if vpcSrc == vpcDst {
		srcToDstStr = fmt.Sprintf("%s to %s both of VPC %s", finding.Src.Name(), finding.Dst.Name(), vpcSrc)
	} else {
		srcToDstStr = fmt.Sprintf("%v of VPC %s to %v of VPC %s", finding.Src.Name(), vpcSrc, finding.Dst.Name(),
			vpcDst)
	}
	return fmt.Sprintf("connection %s %s is not responsive", finding.TCPRspDisable.String(), srcToDstStr)
}

// TCP connection with no response
type blockedTCPResponseConnJSON struct {
	src           string             `json:"source"`
	dst           string             `json:"destination"`
	tcpRspDisable connection.Details `json:"tcp-non-responsive"`
}

func (finding *blockedTCPResponseConn) toJSON() any {
	vpcSrc := finding.vpc()[0]
	vpcDst := finding.vpc()[1]
	res := blockedTCPResponseConnJSON{src: vpcSrc + deliminator + finding.Src.Name(),
		dst: vpcDst + deliminator + finding.Dst.Name(), tcpRspDisable: connection.ToJSON(finding.TCPRspDisable)}
	return res
}
