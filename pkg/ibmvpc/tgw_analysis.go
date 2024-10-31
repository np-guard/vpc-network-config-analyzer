/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"errors"

	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const (
	permitAction = "permit"
	denyAction   = "deny"
)
const defaultPrefixFilter = -1

// getVPCdestSubnetsByAdvertisedRoutes returns a slice of subnets from vpc, which can be destinations of the
// transit gateway tg, based on its available routes (as determined by prefix filters and matched address prefixes)
func getVPCdestSubnetsByAdvertisedRoutes(tg *TransitGateway, vpc *commonvpc.VPC) (res []*commonvpc.Subnet) {
	for _, subnet := range vpc.Subnets() {
		if isSubnetTGWDestination(tg, subnet) {
			res = append(res, subnet)
		}
	}
	return res
}

func isSubnetTGWDestination(tg *TransitGateway, subnet *commonvpc.Subnet) bool {
	dstIPB := subnet.IPblock
	// TODO: routesListPerVPC is currently restricted only to the subnet's VPC, but with
	// overlapping address prefixes the TGW may choose available route from a different VPC
	routesListPerVPC := tg.availableRoutes[subnet.VPCRef.UID()]
	for _, routeCIDR := range routesListPerVPC {
		if dstIPB.IsSubset(routeCIDR) {
			return true
		}
	}
	return false
}

// getVPCAdvertisedRoutes returns a list of IPBlock objects for vpc address prefixes matched by prefix filters (with permit action),
// thus advertised to a TGW.
// It also returns map from IPBlock objects to RulesInTable with index of the transit connection
// and index of the prefix rules within the connection that determines the connection between src and dst
// Note that there is always a single prefix filter that determines the route (allow/deny) for each address prefix
// (could be the default); this is since each atomic src/dst is an endpoint and since
// prefix filter rules do not include protocol or ports (unlike nacls and sgs)
func getVPCAdvertisedRoutes(tc *datamodel.TransitConnection, tcIndex int, vpc *commonvpc.VPC) (advertisedRoutesRes []*netset.IPBlock,
	vpcAPToPrefixRules map[*netset.IPBlock]vpcmodel.RulesInTable, err error) {
	vpcAPToPrefixRules = map[*netset.IPBlock]vpcmodel.RulesInTable{}
	for _, ap := range vpc.AddressPrefixesList {
		filterIndex, isPermitAction, err := getMatchedFilterIndexAndAction(ap, tc)
		if err != nil {
			return nil, nil, err
		}
		apIPBlock, err := netset.IPBlockFromCidr(ap)
		if err != nil {
			return nil, nil, err
		}
		// advertisedRoutesRes contains only address prefixes with allowing action
		var ruleType vpcmodel.RulesType = vpcmodel.OnlyAllow
		if isPermitAction {
			advertisedRoutesRes = append(advertisedRoutesRes, apIPBlock)
		} else {
			ruleType = vpcmodel.OnlyDeny
		}
		vpcAPToPrefixRules[apIPBlock] = vpcmodel.RulesInTable{TableIndex: tcIndex, Rules: []int{filterIndex}, RulesOfType: ruleType}
	}
	return advertisedRoutesRes, vpcAPToPrefixRules, nil
}

// return for a given address-prefix (input cidr) the matching prefix-filter index and its action (allow = true/deny = false)
// if there is no specific prefix filter then gets the details of the configured default prefix filter
func getMatchedFilterIndexAndAction(cidr string, tc *datamodel.TransitConnection) (returnedFilterIndex int,
	action bool, err error) {
	// Array of prefix route filters for a transit gateway connection. This is order dependent with those first in the
	// array being applied first, and those at the end of the array is applied last, or just before the default.
	pfList := tc.PrefixFilters

	// Default setting of permit or deny which applies to any routes that don't match a specified filter.
	pfDefault := tc.PrefixFiltersDefault

	// TODO: currently ignoring the "Before" field of each PrefixFilter, since assuming the array is ordered
	// iterate by order the array of prefix route filters
	for filterIndex, pf := range pfList {
		match, err1 := prefixLeGeMatch(pf.Prefix, pf.Le, pf.Ge, cidr)
		if err1 != nil {
			return defaultPrefixFilter, false, err1
		}
		if match {
			action, err = parseActionString(pf.Action)
			return filterIndex, action, err
		}
	}
	// no match by pfList -- use default
	action, err = parseActionString(pfDefault)
	return defaultPrefixFilter, action, err
}

func parseActionString(action *string) (bool, error) {
	if action == nil {
		return false, errors.New("invalid empty action on prefix filter")
	}
	switch *action {
	case permitAction:
		return true, nil
	case denyAction:
		return false, nil
	default:
		return false, errors.New("prefix filter action should be permit or deny")
	}
}

// LE/GE: Without either, an entry will match an exact prefix.
// The le parameter can be included to match all more-specific prefixes within a parent prefix up to a certain length.
// For example, 10.0.0.0/24 le 30 will match 10.0.0.0/24 and all prefixes contained therein with a length of 30 or less.
// (see https://packetlife.net/blog/2010/feb/1/understanding-ip-prefix-lists/ )

// prefixLeGeMatch checks if a vpc's address-prefix cidr is matched by a given rule's prefix with le/ge attributes
func prefixLeGeMatch(prefix *string, le, ge *int64, cidr string) (bool, error) {
	prefixIPBlock, cidrBlock, err := netset.PairCIDRsToIPBlocks(*prefix, cidr)
	if err != nil {
		return false, err
	}
	subnetCIDRLen, err := cidrBlock.PrefixLength()
	if err != nil {
		return false, err
	}
	switch {
	case ge == nil && le == nil:
		return cidrBlock.Equal(prefixIPBlock), nil
	case ge == nil:
		return cidrBlock.IsSubset(prefixIPBlock) && subnetCIDRLen <= *le, nil
	case le == nil:
		return cidrBlock.IsSubset(prefixIPBlock) && subnetCIDRLen >= *ge, nil
	default:
		return cidrBlock.IsSubset(prefixIPBlock) && subnetCIDRLen >= *ge && subnetCIDRLen <= *le, nil
	}
}
