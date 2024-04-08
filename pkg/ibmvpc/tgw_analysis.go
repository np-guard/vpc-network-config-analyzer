package ibmvpc

import (
	"errors"

	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/models/pkg/ipblock"
)

const (
	permitAction = "permit"
	denyAction   = "deny"
)

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

// getVPCAdvertisedRoutes returns a list of IPBlock objects for vpc address prefixes matched by prefix filters,
// thus advertised to a TGW
func getVPCAdvertisedRoutes(tc *datamodel.TransitConnection, vpc *VPC) (res []*ipblock.IPBlock, err error) {
	validateAddressPrefixesExist(vpc)
	for _, ap := range vpc.addressPrefixes {
		matched, err := isCIDRMatchedByPrefixFilters(ap, tc)
		if err != nil {
			return nil, err
		}
		if matched {
			apIPBlock, err := ipblock.FromCidr(ap)
			if err != nil {
				return nil, err
			}
			res = append(res, apIPBlock)
		}
	}
	return res, nil
}

func isCIDRMatchedByPrefixFilters(cidr string, tc *datamodel.TransitConnection) (bool, error) {
	// Array of prefix route filters for a transit gateway connection. This is order dependent with those first in the
	// array being applied first, and those at the end of the array is applied last, or just before the default.
	pfList := tc.PrefixFilters

	// Default setting of permit or deny which applies to any routes that don't match a specified filter.
	pfDefault := tc.PrefixFiltersDefault

	// TODO: currently assuming subnet cidrs are the advertised routes to the TGW, matched against the prefix filters
	// TODO: currently ignoring the "Before" field of each PrefixFilter, since assuming the array is ordered
	// iterate by order the array of prefix route filters
	for _, pf := range pfList {
		match, err := prefixLeGeMatch(pf.Prefix, pf.Le, pf.Ge, cidr)
		if err != nil {
			return false, err
		}
		if match {
			return parseActionString(pf.Action)
		}
	}
	// no match by pfList -- use default
	return parseActionString(pfDefault)
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

// the following functions are related to explainability structs

// gets a map from address prefixes of the vpc to matching prefix of tgw, if any
func getVpcApsPrefixes(tc *datamodel.TransitConnection, vpc *VPC) (res map[*ipblock.IPBlock]tgwPrefixFilter, err error) {
	validateAddressPrefixesExist(vpc) // todo tmp WA copied from getVPCAdvertisedRoutes so that this func is self contained
	res = map[*ipblock.IPBlock]tgwPrefixFilter{}
	for _, ap := range vpc.addressPrefixes {
		prefixIndex, err1 := getCIDRPrefixFilter(ap, tc)
		if err1 != nil {
			return nil, err1
		}
		apIPBlock, err2 := ipblock.FromCidr(ap)
		if err2 != nil {
			return nil, err2
		}
		res[apIPBlock] = tgwPrefixFilter{tc, prefixIndex}
	}
	return res, nil
}

// gets for a cidr the tgw's prefix's index that matches it, -1 if non match
func getCIDRPrefixFilter(cidr string, tc *datamodel.TransitConnection) (int, error) {
	// TODO: currently assuming subnet cidrs are the advertised routes to the TGW, matched against the prefix filters
	// TODO: currently ignoring the "Before" field of each PrefixFilter, since assuming the array is ordered
	// iterate by order the array of prefix route filters
	for i, pf := range tc.PrefixFilters {
		match, err := prefixLeGeMatch(pf.Prefix, pf.Le, pf.Ge, cidr)
		if err != nil {
			return minusOne, err
		}
		if match {
			return i, nil
		}
	}
	// no match by pfList -- use default
	return minusOne, nil
}
