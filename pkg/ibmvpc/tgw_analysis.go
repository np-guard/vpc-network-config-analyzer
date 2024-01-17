package ibmvpc

import (
	"errors"

	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

const (
	permitAction = "permit"
	denyAction   = "deny"
)

// given a TransitConnection object, analyze its prefix filters, and get the permitted set of subnets
// from the VPC to be connected via the TGW
func getTransitConnectionFiltersForVPC(tc *datamodel.TransitConnection, vpc *VPC) (map[string]bool, error) {
	res := map[string]bool{}
	for _, subnet := range vpc.subnets() {
		matched, err := isSubnetMatchedByPrefixFilters(subnet, tc)
		if nil != err {
			return nil, err
		}
		if matched {
			res[subnet.UID()] = true
		}
	}
	return res, nil
}

func isSubnetMatchedByPrefixFilters(subnet *Subnet, tc *datamodel.TransitConnection) (bool, error) {
	// Array of prefix route filters for a transit gateway connection. This is order dependent with those first in the
	// array being applied first, and those at the end of the array is applied last, or just before the default.
	pfList := tc.PrefixFilters

	// Default setting of permit or deny which applies to any routes that don't match a specified filter.
	pfDefault := tc.PrefixFiltersDefault

	// TODO: currently assuming subnet cidrs are the advertised routes to the TGW, matched against the prefix filters
	// TOTO: currently ignoring the "Before" field of each PrefixFilter, since assuming the array is ordered
	// iterate by order the array of prefix route filters
	for _, pf := range pfList {
		match, err := prefixLeGeMatch(pf.Prefix, pf.Le, pf.Ge, subnet)
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

/*
// TransitGatewayConnectionPrefixFilter : A prefix filter for a Transit Gateway connection.
type TransitGatewayConnectionPrefixFilter struct {
	// Whether to permit or deny prefix filter.
	Action *string `json:"action" validate:"required"`

	// IP Prefix GE.
	Ge *int64 `json:"ge,omitempty"`

	// IP Prefix LE.
	Le *int64 `json:"le,omitempty"`

	// IP Prefix.
	Prefix *string `json:"prefix" validate:"required"`
}
*/

// prefixLeGeMatch checks if a subnet cidr is matched by a given prefix with le/ge attributes
func prefixLeGeMatch(prefix *string, le, ge *int64, subnet *Subnet) (bool, error) {
	prefixIPBlock := common.NewIPBlockFromCidr(*prefix)
	subnetCIDR := subnet.AddressRange()
	subnetCIDRLen, err := subnetCIDR.PrefixLength()
	if err != nil {
		return false, err
	}
	switch {
	case ge == nil && le == nil:
		return subnetCIDR.Equal(prefixIPBlock), nil
	case ge == nil:
		return subnetCIDR.ContainedIn(prefixIPBlock) && subnetCIDRLen <= *le, nil
	case le == nil:
		return subnetCIDR.ContainedIn(prefixIPBlock) && subnetCIDRLen >= *ge, nil
	default:
		return subnetCIDR.ContainedIn(prefixIPBlock) && subnetCIDRLen >= *ge && subnetCIDRLen <= *le, nil
	}
}
