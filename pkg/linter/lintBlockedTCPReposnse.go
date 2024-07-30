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
const deliminator = "/"

// overlapSubnets: overlapping subnet ranges (relevant mostly for the multiple VPCs use case)
type blockedTCPResponseLint struct {
	connectionLinter
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
func (lint *blockedTCPResponseLint) lintName() string {
	return blockedTCPResponse
}

func (lint *blockedTCPResponseLint) lintDescription() string {
	return "Blocked TCP response"
}

func (lint *blockedTCPResponseLint) check() error {
	for i := range lint.nodesConn {
		for i2 := range lint.nodesConn[i].GroupedConnectivity.GroupedLines {
			tcpRspDisable := lint.nodesConn[i].GroupedConnectivity.GroupedLines[i2].CommonProperties.Conn.TCPRspDisable
			if !tcpRspDisable.IsEmpty() {
				lint.addFinding(&blockedTCPResponseConn{src: lint.nodesConn[i].GroupedConnectivity.GroupedLines[i2].Src,
					dst: lint.nodesConn[i].GroupedConnectivity.GroupedLines[i2].Dst, tcpRspDisable: tcpRspDisable})
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
	vpcSrcName := finding.vpc()[0].Name()
	vpcDstName := finding.vpc()[1].Name()

	srcToDstStr := fmt.Sprintf("from %v%s%s to %v%s%s",
		vpcSrcName, deliminator, finding.src.Name(), vpcDstName, deliminator, finding.dst.Name())

	return fmt.Sprintf("In the connection %s %s response is blocked", srcToDstStr,
		strings.ReplaceAll(finding.tcpRspDisable.String(), "protocol: ", ""))
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
