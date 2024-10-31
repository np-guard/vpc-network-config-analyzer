/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/netset"
)

func newNetIntForPathTest() *mockNetIntf {
	return &mockNetIntf{name: "vsi1[10.10.2.6]", cidr: "10.10.2.6"}
}

func newIPBlock(inputCIDROrAddress string) *netset.IPBlock {
	res, _ := netset.IPBlockFromCidrOrAddress(inputCIDROrAddress)
	return res
}

type testPath struct {
	name           string
	p              Path
	pathString     string
	otherPath      Path
	otherPathEqual bool
}

func (tt *testPath) run(t *testing.T) {
	if tt.pathString != "" {
		require.Equal(t, tt.pathString, tt.p.String())
	}
	if len(tt.otherPath) > 0 {
		require.Equal(t, tt.otherPathEqual, tt.p.Equal(tt.otherPath))
		require.True(t, !tt.otherPath.Empty())
	} else {
		require.True(t, tt.otherPath.Empty())
	}
}

var testPathList = []*testPath{
	// tests for paths string
	{
		name: "check path string with src Netintf and dst IPBlock",
		p: Path([]*Endpoint{{VpcResource: newNetIntForPathTest()},
			{IPBlock: newIPBlock("10.10.2.5/32")}}),

		pathString: "NetworkInterface - vsi1[10.10.2.6] -> 10.10.2.5",
	},
	{
		name: "check path string with src Netintf and nextHop afterwards",
		p: Path([]*Endpoint{{VpcResource: newNetIntForPathTest()},
			{NextHop: &NextHopEntry{
				NextHop:  newIPBlock("10.11.2.5"),
				OrigDest: newIPBlock("10.12.2.5"),
			}}}),

		pathString: "NetworkInterface - vsi1[10.10.2.6] -> nextHop: 10.11.2.5 [origDest: 10.12.2.5]",
	},

	// tests for paths equal/not-equal
	{
		name: "check path equality should be true",
		p: Path([]*Endpoint{{VpcResource: newNetIntForPathTest()},
			{IPBlock: newIPBlock("10.10.2.5/32")}}),

		otherPath: Path([]*Endpoint{{VpcResource: newNetIntForPathTest()},
			{IPBlock: newIPBlock("10.10.2.5/32")}}),

		otherPathEqual: true,
	},
	{
		name: "check path equality should be false",
		p: Path([]*Endpoint{{VpcResource: newNetIntForPathTest()},
			{IPBlock: newIPBlock("10.10.2.5/32")}}),

		otherPath: Path([]*Endpoint{{VpcResource: newNetIntForPathTest()},
			{IPBlock: newIPBlock("10.11.2.5/32")}}),

		otherPathEqual: false,
	},
}

func TestPathMethods(t *testing.T) {
	t.Parallel()
	for idx := range testPathList {
		test := testPathList[idx]
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			test.run(t)
		})
	}
}
