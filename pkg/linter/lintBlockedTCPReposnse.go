/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

const blockedTCPResponse = "blocked-TCP-response"

// overlapSubnets: overlapping subnet ranges (relevant mostly for the multiple VPCs use case)
type blockedTCPResponseLint struct {
	connectionLinter
}

// TCP connection with no response
type blockedTCPResonseConn struct {
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
	return nil
}

///////////////////////////////////////////////////////////
// finding interface implementation for overlapSubnets
//////////////////////////////////////////////////////////

func (finding *blockedTCPResonseConn) vpc() []string {
	return nil
}

func (finding *blockedTCPResonseConn) string() string {
	return ""
}

func (finding *blockedTCPResonseConn) toJSON() any {
	return nil
}
