/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type testDisjointRouting struct {
	testName              string
	routesList            []*route
	expectedRoutingOutput string
}

// disjointRoutingStr is used for testing, currently assuming all routes are with empty zone str
func (rt *routingTable) disjointRoutingStr() string {
	lines := []string{}
	for dest, nextHop := range rt.routingResultMap[""].nextHops {
		lines = append(lines, fmt.Sprintf("%s -> %s", dest.ToIPRanges(), nextHop.ToIPAddressString()))
	}
	for _, droppedDest := range rt.routingResultMap[""].droppedDestinations.ToCidrList() {
		lines = append(lines, fmt.Sprintf("%s -> drop", droppedDest))
	}
	for _, delegatedDest := range rt.routingResultMap[""].delegatedDestinations.ToCidrList() {
		lines = append(lines, fmt.Sprintf("%s -> delegate", delegatedDest))
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

func (test *testDisjointRouting) run(t *testing.T) {
	rt, err := newRoutingTable(test.routesList, nil, &vpcmodel.VPCResource{})
	require.Nil(t, err)
	require.Equal(t, test.expectedRoutingOutput, rt.disjointRoutingStr())
}

// newRouteNoErr returns new route with advertise=false, and without checking error returned
func newRouteNoErr(name, dest, nextHop string, action routingAction, prio int, zone string) *route {
	res, _ := newRoute(name, dest, nextHop, zone, action, prio, false)
	return res
}

var disjointRoutingTests = []*testDisjointRouting{
	{
		testName: "routing splits range to delegate and deliver",
		routesList: []*route{
			newRouteNoErr("r1", "10.10.0.0/16", "", delegate, 2, ""),
			newRouteNoErr("r2", "10.11.0.0/16", "", delegate, 2, ""),
			newRouteNoErr("r3", "0.0.0.0/0", "10.10.1.5", deliver, 2, ""), // cidrs from r1,r2 not determined by this route
		},
		expectedRoutingOutput: `0.0.0.0-10.9.255.255 -> 10.10.1.5
10.10.0.0/15 -> delegate
10.12.0.0-255.255.255.255 -> 10.10.1.5`,
	},

	{
		testName: "test higher priority takes effect on same dest cidr: deliver instead of delegate",
		routesList: []*route{
			newRouteNoErr("r1", "10.10.0.0/16", "", delegate, 2, ""),
			newRouteNoErr("r2", "10.11.0.0/16", "", delegate, 2, ""),
			newRouteNoErr("r4", "10.11.0.0/16", "10.10.1.5", deliver, 1, ""), // higher priority over r2
			newRouteNoErr("r3", "0.0.0.0/0", "10.10.1.5", deliver, 2, ""),
		},
		expectedRoutingOutput: `0.0.0.0-10.9.255.255 -> 10.10.1.5
10.10.0.0/16 -> delegate
10.11.0.0-10.11.255.255 -> 10.10.1.5
10.12.0.0-255.255.255.255 -> 10.10.1.5`,
	},

	{
		testName: "test lower priority does not effect on same dest cidr: delegate instead of deliver",
		routesList: []*route{
			newRouteNoErr("r1", "10.10.0.0/16", "", delegate, 2, ""),
			newRouteNoErr("r2", "10.11.0.0/16", "", delegate, 2, ""),
			newRouteNoErr("r4", "10.11.0.0/16", "10.10.1.5", deliver, 3, ""), // lower priority than r2
			newRouteNoErr("r3", "0.0.0.0/0", "10.10.1.5", deliver, 2, ""),
		},
		expectedRoutingOutput: `0.0.0.0-10.9.255.255 -> 10.10.1.5
10.10.0.0/15 -> delegate
10.12.0.0-255.255.255.255 -> 10.10.1.5`,
	},

	{
		testName: "test redundant route, more specific cidrs take effect: delegate instead of deliver",
		routesList: []*route{
			newRouteNoErr("r1", "10.10.0.0/16", "", delegate, 2, ""),
			newRouteNoErr("r2", "10.11.0.0/16", "", delegate, 2, ""),
			newRouteNoErr("r4", "10.10.0.0/15", "10.10.1.5", deliver, 2, ""), // redundant route, more specific cidrs in r1, r2
			newRouteNoErr("r3", "0.0.0.0/0", "10.10.1.5", deliver, 2, ""),
		},
		expectedRoutingOutput: `0.0.0.0-10.9.255.255 -> 10.10.1.5
10.10.0.0/15 -> delegate
10.12.0.0-255.255.255.255 -> 10.10.1.5`,
	},
}

func TestComputeDisjointRoutingNew(t *testing.T) {
	t.Parallel()
	for idx := range disjointRoutingTests {
		test := disjointRoutingTests[idx]
		t.Run(test.testName, func(t *testing.T) {
			t.Parallel()
			test.run(t)
		})
	}
}
