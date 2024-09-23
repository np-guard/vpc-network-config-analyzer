/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/ipblock"
)

// routing_paths: this file contains types for representing routing paths and their endpoints
// a routing path is used to capture how traffic is routed within VPCs resources, given a src->dst pair

// Path captures a list of endpoints within a routing Path.
// The first endpoint is the src. The last endpoint is dest, or a nextHopEntry element.
type Path []*Endpoint

// Endpoint captures possible types for elements within routing paths: concrete vpc resource, IP Address, and nextHopEntry
type Endpoint struct {
	VpcResource VPCResourceIntf
	IPBlock     *ipblock.IPBlock
	NextHop     *NextHopEntry
	TargetVPC   string // if the VpcResource is tgw, the targetVPC is also assigned
}

// NextHopEntry captures an endpoint within a routing path, which redirects traffic to its nextHop instead of the original dest
type NextHopEntry struct {
	NextHop  *ipblock.IPBlock // the next hop address
	OrigDest *ipblock.IPBlock // the original destination
	// rt       *routingTable    // the routing table from which this next hop was determined
}

const pathConnector string = " -> "

func (p Path) String() string {
	return strings.Join(p.listEndpointsStrings(), pathConnector)
}

func (p Path) Empty() bool {
	return len(p) == 0
}

// ConcatPaths returns a new path concatenating the passed in paths
func ConcatPaths(paths ...Path) Path {
	return slices.Concat(paths...)
}

func (p Path) PrependResource(resource VPCResourceIntf) Path {
	return ConcatPaths(PathFromResource(resource), p)
}

func PathFromResource(resource VPCResourceIntf) Path {
	return Path{{VpcResource: resource}}
}

func PathFromIPBlock(ipb *ipblock.IPBlock) Path {
	return Path{{IPBlock: ipb}}
}

func PathFromTGWResource(tgw VPCResourceIntf, targetVPC string) Path {
	return Path{{VpcResource: tgw, TargetVPC: targetVPC}}
}

func (p Path) DoesEndWithTGW() bool {
	return len(p) > 0 && p[len(p)-1].VpcResource != nil &&
		p[len(p)-1].VpcResource.Kind() == "TGW" // TODO: use const
}

func (p Path) TargetVPC() string {
	if !p.DoesEndWithTGW() {
		return ""
	}
	return p[len(p)-1].TargetVPC
}

func (p Path) listEndpointsStrings() []string {
	res := make([]string, len(p))
	for i := range p {
		res[i] = p[i].string()
	}
	return res
}

func (p Path) Equal(otherPath Path) bool {
	if len(p) != len(otherPath) {
		return false
	}
	for i := range p {
		if !p[i].equal(otherPath[i]) {
			return false
		}
	}
	return true
}

func (e *Endpoint) string() string {
	switch {
	case e.VpcResource != nil:
		return fmt.Sprintf("%s - %s", e.VpcResource.Kind(), e.VpcResource.NameForAnalyzerOut(nil))
	case e.IPBlock != nil:
		return e.IPBlock.String()
	case e.NextHop != nil:
		return e.NextHop.string()
	}
	return ""
}

func (e *Endpoint) equal(otherEndpoint *Endpoint) bool {
	switch {
	case e.NextHop != nil:
		if otherEndpoint.NextHop == nil || !otherEndpoint.NextHop.equal(e.NextHop) {
			return false
		}
	case e.VpcResource != nil:
		if otherEndpoint.VpcResource == nil || otherEndpoint.VpcResource.UID() != e.VpcResource.UID() {
			return false
		}
	case e.IPBlock != nil:
		if otherEndpoint.IPBlock == nil || !e.IPBlock.Equal(otherEndpoint.IPBlock) {
			return false
		}
	default:
		return false // should not get here
	}
	return true
}

func (n *NextHopEntry) string() string {
	return fmt.Sprintf("nextHop: %s [origDest: %s]", n.NextHop.String(), n.OrigDest.String())
}

func (n *NextHopEntry) equal(other *NextHopEntry) bool {
	return n.NextHop.Equal(other.NextHop) &&
		n.OrigDest.Equal(other.OrigDest)
	// TODO: add comparison of rt ?
}
