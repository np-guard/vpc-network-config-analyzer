/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"errors"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/models/pkg/ipblock"
)

const (
	permitAction = "permit"
	denyAction   = "deny"
)
const defaultPrefixFilter = -1

// getVPCdestSubnetsByAdvertisedRoutes returns a slice of subnets from vpc, which can be destinations of the
// transit gateway tg, based on its available routes (as determined by prefix filters and matched address prefixes)
func getVPCdestSubnetsByAdvertisedRoutes(tg *TransitGateway, vpc *VPC) (res []*Subnet) {
	for _, subnet := range vpc.subnets() {
		if isSubnetTGWDestination(tg, subnet) {
			res = append(res, subnet)
		}
	}
	return res
}

func isSubnetTGWDestination(tg *TransitGateway, subnet *Subnet) bool {
	dstIPB := subnet.ipblock
	// TODO: routesListPerVPC is currently restricted only to the subnet's VPC, but with
	// overlapping address prefixes the TGW may choose available route from a different VPC
	routesListPerVPC := tg.availableRoutes[subnet.VPCRef.UID()]
	for _, routeCIDR := range routesListPerVPC {
		if dstIPB.ContainedIn(routeCIDR) {
			return true
		}
	}
	return false
}

// TODO: remove this functions when all relevant TGW tests contain input address prefixes that do not overlap
func validateAddressPrefixesExist(vpc *VPC) {
	if len(vpc.addressPrefixes) == 0 {
		// temp work around -- adding subnets as the vpc's address prefixes, for current tests missing address prefixes
		for _, subnet := range vpc.subnetsList {
			vpc.addressPrefixes = append(vpc.addressPrefixes, subnet.cidr)
		}
	}
}

// getVPCAdvertisedRoutes returns a list of IPBlock objects for vpc address prefixes matched by prefix filters (with permit action),
// thus advertised to a TGW.
// It also returns list of IPBlockPrefixFilter objects, with details per address prefix of the matched prefix filter
func getVPCAdvertisedRoutes(tc *datamodel.TransitConnection, tcIndex int, vpc *VPC) (advertisedRoutesRes []*ipblock.IPBlock,
	vpcApsPrefixesRes []IPBlockPrefixFilter, // todo remove
	vpcAPToPrefixRules map[*ipblock.IPBlock]vpcmodel.RulesInFilter, err error) {
	validateAddressPrefixesExist(vpc)
	vpcApsPrefixesRes = make([]IPBlockPrefixFilter, len(vpc.addressPrefixes))
	vpcAPToPrefixRules = map[*ipblock.IPBlock]vpcmodel.RulesInFilter{}
	for i, ap := range vpc.addressPrefixes {
		filterIndex, isPermitAction, err := getMatchedFilterIndexAndAction(ap, tc)
		if err != nil {
			return nil, nil, nil, err
		}
		apIPBlock, err := ipblock.FromCidr(ap)
		if err != nil {
			return nil, nil, nil, err
		}
		// advertisedRoutesRes contains only address prefixes with allowing action
		var ruleType vpcmodel.RulesType = vpcmodel.OnlyAllow
		if isPermitAction {
			advertisedRoutesRes = append(advertisedRoutesRes, apIPBlock) // todo remove
		} else {
			ruleType = vpcmodel.OnlyDeny
		}
		vpcAPToPrefixRules[apIPBlock] = vpcmodel.RulesInFilter{Table: tcIndex, Rules: []int{filterIndex}, RulesFilterType: ruleType}
		vpcApsPrefixesRes[i] = IPBlockPrefixFilter{apIPBlock, tgwPrefixFilter{tc, filterIndex}}
	}
	return advertisedRoutesRes, vpcApsPrefixesRes, nil, nil
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
	prefixIPBlock, cidrBlock, err := ipblock.PairCIDRsToIPBlocks(*prefix, cidr)
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
		return cidrBlock.ContainedIn(prefixIPBlock) && subnetCIDRLen <= *le, nil
	case le == nil:
		return cidrBlock.ContainedIn(prefixIPBlock) && subnetCIDRLen >= *ge, nil
	default:
		return cidrBlock.ContainedIn(prefixIPBlock) && subnetCIDRLen >= *ge && subnetCIDRLen <= *le, nil
	}
}
