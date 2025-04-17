/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package ibmvpc

import (
	"fmt"
	"slices"
	"sort"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"github.com/np-guard/models/pkg/netset"
)

// ///////////////////////////////////////////////////////////////////////
// connection from and to load balancer are done via private IPs
// created to it upon its deployment.
// However, when a load balancer is deployed,
// Private IPs are not created for all the load balancer subnets.
// To understand and monitor the connectivity that is potentially induced by the load balancer,
// we create a private IP for all the load balancer subnets.
// (we calls these private IPs potential private Ips)
// Moreover, if a filter rule splits the subnet's cidr to few blocks, we want to create private ip per each such block.

// To create a private IP which does not exist in the config, we need an unused address.
// subnetsIPBlocks has two main purposes:
//   1. for each subnet, it calculates splitByFiltersBlocks - the atomic blocks induced by the filters.
//      splitByFiltersBlocks are such that:
//   		a. the blocks are disjoint
//	    	b. the union of the blocks is the subnet cidr
//      we calculate splitByFiltersBlocks of a subnet by:
//          (a) collecting all the filters' rules blocks.
//          (b) adding allCidr block to these blocks.
//          (c) from these blocks, create a list of disjoint blocks
//          (d) for each of these blocks, intersect the block with the subnet cidr
//          (e) collect all the non-empty intersections we get in (d)
//   2. allocate a free address for the potential private IPs - to this end, we hold for each subnet freeAddressesBlocks,
//      freeAddressesBlocks are splitByFiltersBlocks minus all the addresses that were already allocated.
//      to get freeAddressesBlocks, we first copy splitByFiltersBlocks, then we remove the subnet already allocated addresses.
//      (we get these addresses from the subnet reserved IP).
//       when a free address is needed, we take the first address of the block and remove it from the free blocks list.

// /////////////////////////////////////////////////////////////////////////////////////////
// oneSubnetBlocks hold the blocks of one subnet
type oneSubnetBlocks struct {
	subnetOriginalBlock *netset.IPBlock // the block of the cidr of the subnet
	// splitByFiltersBlocks are the atomic blocks induced by the filters, the union of this slice is the subnetOriginalBlock
	splitByFiltersBlocks []*netset.IPBlock
	// freeAddressesBlocks are the splitByFiltersBlocks minus the reserved IPs
	// each block in splitByFiltersBlocks has a corresponding block at freeAddressesBlocks
	freeAddressesBlocks []*netset.IPBlock
	// fullyReservedBlocks is a bool per block.
	// its true if all the addresses in the original block are reserved IP
	// for these blocks there is no need to create private IPs
	fullyReservedBlocks []bool
}

// subnetsIPBlocks is a map from the subnet crn to the subnets block
type subnetsIPBlocks map[string]*oneSubnetBlocks

// getSubnetsIPBlocks() is the main func that creates the subnetsBlocks, steps:
// 1. get the subnets original blocks
// 2. calculate the filters blocks
// 3. calculate the splitByFiltersBlocks
// 4. calculate the freeAddressesBlocks
func getSubnetsIPBlocks(rc *IBMresourcesContainer, filtersCidrs []map[string][]*string,
	skipByVPC map[string]bool) (subnetsIPBlocks, error) {
	subnetsBlocks := subnetsIPBlocks{}
	// gets the original blocks of the subnets:
	if err := subnetsBlocks.getSubnetsOriginalBlocks(rc, skipByVPC); err != nil {
		return nil, err
	}
	// calc the filters blocks:
	filtersBlocks, err := getFiltersBlocks(filtersCidrs)
	if err != nil {
		return nil, err
	}
	// calc the splitByFiltersBlocks:
	subnetsBlocks.splitSubnetsOriginalBlocks(rc, filtersBlocks, skipByVPC)
	// calc the freeAddressesBlocks:
	if err := subnetsBlocks.getSubnetsFreeBlocks(rc, skipByVPC); err != nil {
		return nil, err
	}
	return subnetsBlocks, nil
}

func (subnetsBlocks subnetsIPBlocks) getSubnetsOriginalBlocks(rc *IBMresourcesContainer,
	skipByVPC map[string]bool) (err error) {
	for _, subnetObj := range rc.SubnetList {
		if skipByVPC[*subnetObj.VPC.ID] {
			continue
		}
		subnetsBlocks[*subnetObj.CRN] = &oneSubnetBlocks{}
		subnetsBlocks[*subnetObj.CRN].subnetOriginalBlock, err = netset.IPBlockFromCidr(*subnetObj.Ipv4CIDRBlock)
		if err != nil {
			return err
		}
	}
	return nil
}

// splitSubnetsOriginalBlocks() splits the subnet's cidr(s) to (maximal) disjoint blocks -
// such that each block is atomic w.r.t. the filters rules
func (subnetsBlocks subnetsIPBlocks) splitSubnetsOriginalBlocks(rc *IBMresourcesContainer,
	filtersBlocks filtersBlocks, skipByVPC map[string]bool) {
	for _, subnetObj := range rc.SubnetList {
		if skipByVPC[*subnetObj.VPC.ID] {
			continue
		}
		subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks =
			splitSubnetOriginalBlock(subnetsBlocks[*subnetObj.CRN].subnetOriginalBlock, filtersBlocks[*subnetObj.VPC.CRN])
	}
}

// splitSubnetsOriginalBlocks() splits one subnet's cidr(s) to (maximal) disjoint blocks -
// such that each block is atomic w.r.t. the filters rules
func splitSubnetOriginalBlock(subnetOriginalBlock *netset.IPBlock, filtersBlocks []*netset.IPBlock) []*netset.IPBlock {
	filtersBlocksOnSubnet := []*netset.IPBlock{}
	for _, filterBlock := range filtersBlocks {
		filterBlocksOnSubnet := subnetOriginalBlock.Intersect(filterBlock)
		if !filterBlocksOnSubnet.IsEmpty() {
			filtersBlocksOnSubnet = append(filtersBlocksOnSubnet, filterBlocksOnSubnet)
		}
	}
	return filtersBlocksOnSubnet
}

// getSubnetsFreeBlocks() - calcs all the addresses that are not allocated:
// for each subnet:
//  1. make a copy of the splitByFiltersBlocks
//  2. remove from this copy the addresses that were already allocated
//  3. set fullyReservedBlocks - check for each block if it has free addresses
func (subnetsBlocks subnetsIPBlocks) getSubnetsFreeBlocks(rc *IBMresourcesContainer, skipByVPC map[string]bool) error {
	for _, subnetObj := range rc.SubnetList {
		if skipByVPC[*subnetObj.VPC.ID] {
			continue
		}
		subnetsBlocks[*subnetObj.CRN].freeAddressesBlocks = make([]*netset.IPBlock, len(subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks))
		subnetsBlocks[*subnetObj.CRN].fullyReservedBlocks = make([]bool, len(subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks))
		for blockIndex, block := range subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks {
			subnetsBlocks[*subnetObj.CRN].freeAddressesBlocks[blockIndex] = block.Copy()
		}
		// all the allocated IPs are at subnetObj.ReservedIps.
		for blockIndex := range subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks {
			for _, reservedIP := range subnetObj.ReservedIps {
				if err := subnetsBlocks.removeAddressFromFree(*reservedIP.Address, *subnetObj.CRN, blockIndex); err != nil {
					return err
				}
			}
		}
		for blockIndex := range subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks {
			if subnetsBlocks[*subnetObj.CRN].freeAddressesBlocks[blockIndex].IsEmpty() {
				subnetsBlocks[*subnetObj.CRN].fullyReservedBlocks[blockIndex] = true
			}
		}
	}
	return nil
}

// allocSubnetFreeAddress() allocated a free address from a block (for the private ip):
func (subnetsBlocks subnetsIPBlocks) allocSubnetFreeAddress(subnetCRN string, blockIndex int) (string, error) {
	if subnetsBlocks[subnetCRN].freeAddressesBlocks[blockIndex].IsEmpty() {
		return "", fmt.Errorf("fail to allocate a free address at block: %s ", subnetsBlocks[subnetCRN].freeAddressesBlocks[blockIndex].String())
	}
	address := subnetsBlocks[subnetCRN].freeAddressesBlocks[blockIndex].FirstIPAddress()
	return address, subnetsBlocks.removeAddressFromFree(address, subnetCRN, blockIndex)
}
func (subnetsBlocks subnetsIPBlocks) subnetBlocks(subnetCRN string) []*netset.IPBlock {
	return subnetsBlocks[subnetCRN].splitByFiltersBlocks
}
func (subnetsBlocks subnetsIPBlocks) isFullyReservedBlock(subnetCRN string, blockIndex int) bool {
	return subnetsBlocks[subnetCRN].fullyReservedBlocks[blockIndex]
}

func (subnetsBlocks subnetsIPBlocks) removeAddressFromFree(address, subnetCRN string, blockIndex int) error {
	addressBlock, err := netset.IPBlockFromIPAddress(address)
	if err != nil {
		return err
	}
	subnetsBlocks[subnetCRN].freeAddressesBlocks[blockIndex] =
		subnetsBlocks[subnetCRN].freeAddressesBlocks[blockIndex].Subtract(addressBlock)
	return nil
}

// filtersBlocks is a map from VPC UID to a list of IPBlocks,
// which holds the list of disjoint IPBlocks computed from all referenced CIDRs in that VPC's filters rules
type filtersBlocks map[string][]*netset.IPBlock

// ///////////////////////////////////////////
// getFiltersBlocks() create a slice of disjoint blocks for each vpc, split according to the rules blocks, and their sum is allCidr:
func getFiltersBlocks(filtersCidrs []map[string][]*string) (blocks filtersBlocks, err error) {
	// sorting by vpc:
	vpcCidrs := getVpcsCidrs(filtersCidrs)
	// disjointing:
	return disjointVpcCidrs(vpcCidrs)
}

// getVpcsCidrs() sort the cidr of all filters for each vpc separately, adding netset.CidrAll for every vpc
func getVpcsCidrs(filtersCidrs []map[string][]*string) map[string][]string {
	vpcCidrs := map[string][]string{}
	for _, filterCidrsOrAddresses := range filtersCidrs {
		for vpc, vpcCidrsOrAddresses := range filterCidrsOrAddresses {
			if _, ok := vpcCidrs[vpc]; !ok {
				vpcCidrs[vpc] = []string{netset.CidrAll}
			}
			for _, cidrOrAddress := range vpcCidrsOrAddresses {
				if cidrOrAddress != nil {
					vpcCidrs[vpc] = append(vpcCidrs[vpc], *cidrOrAddress)
				}
			}
		}
	}
	return vpcCidrs
}

// disjointVpcCidrs() disjoint the cidr for each vpc.
func disjointVpcCidrs(cidr map[string][]string) (blocks filtersBlocks, err error) {
	blocks = filtersBlocks{}
	for vpc, vpcCidr := range cidr {
		blocks[vpc], err = disjointCidrs(vpcCidr)
		if err != nil {
			return nil, err
		}
	}
	return blocks, nil
}

// disjointCidrs() get a slice of cidrs/addresses and create a slice of disjoint blocks.
// the algorithm:
//  1. remove duplicate cidrs
//  2. convert the cidr to a slice of blocks
//  3. sort the blocks by size - small to big
//  4. iterate over the blocks: for each block, create a disjoint block by subtracting from the block the former blocks
//
// please notice - there is a method models.DisjointIPBlocks(), this method is not suitable for this case:
// at the output of models.DisjointIPBlocks(), each ipblock must be a range of IPs
func disjointCidrs(cidrs []string) ([]*netset.IPBlock, error) {
	compactCidrs := slices.Compact(cidrs)
	cidrBlocks := make([]*netset.IPBlock, len(compactCidrs))
	for i, cidr := range compactCidrs {
		block, err := netset.IPBlockFromCidrOrAddress(cidr)
		if err != nil {
			return nil, err
		}
		cidrBlocks[i] = block
	}
	sort.Slice(cidrBlocks, func(i, j int) bool {
		// todo - use ipCount() instead of PrefixLength(), after exposing it at modules?
		// till then, we do not need to check the error, we know that this is a one cidr block
		PrefixLengthI, _ := cidrBlocks[i].PrefixLength()
		PrefixLengthJ, _ := cidrBlocks[j].PrefixLength()
		return PrefixLengthI > PrefixLengthJ
	})
	unionOfPreviousBlocks := netset.NewIPBlock()
	disjointBlocks := []*netset.IPBlock{}
	for _, b := range cidrBlocks {
		newBlock := b.Subtract(unionOfPreviousBlocks)
		if !newBlock.IsEmpty() {
			disjointBlocks = append(disjointBlocks, newBlock)
		}
		unionOfPreviousBlocks = unionOfPreviousBlocks.Union(b)
	}
	return disjointBlocks, nil
}

// //////////////////////////////////////////////////
// todo: this file should be at vpcmodel, after moving out the reference to rc *IBMresourcesContainer
// these following three function should be part of the ibmvpc package:
func getACLRulesCidrs(rc *IBMresourcesContainer, skipByVPC map[string]bool) (map[string][]*string, error) {
	cidrs := map[string][]*string{}
	for _, aclObj := range rc.NetworkACLList {
		if skipByVPC[*aclObj.VPC.CRN] {
			continue
		}
		for i, rule := range aclObj.Rules {
			var src, dst *string
			switch ruleObj := rule.(type) {
			case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolAll:
				src = ruleObj.Source
				dst = ruleObj.Destination
			case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolTcpudp:
				src = ruleObj.Source
				dst = ruleObj.Destination
			case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolIcmp:
				src = ruleObj.Source
				dst = ruleObj.Destination
			default:
				return nil, fmt.Errorf("ACL %s has unsupported type for the %dth rule", *aclObj.Name, i)
			}
			if _, ok := cidrs[*aclObj.VPC.CRN]; !ok {
				cidrs[*aclObj.VPC.CRN] = []*string{}
			}
			cidrs[*aclObj.VPC.CRN] = append(cidrs[*aclObj.VPC.CRN], []*string{src, dst}...)
		}
	}
	return cidrs, nil
}

func getGSRulesCidrs(rc *IBMresourcesContainer, skipByVPC map[string]bool) (map[string][]*string, error) {
	cidrs := map[string][]*string{}
	for _, sgObj := range rc.SecurityGroupList {
		if skipByVPC[*sgObj.VPC.CRN] {
			continue
		}
		for i, rule := range sgObj.Rules {
			var localRule, remoteRule interface{}
			switch ruleObj := rule.(type) {
			case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolAll:
				remoteRule = ruleObj.Remote
				localRule = ruleObj.Local
			case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp:
				remoteRule = ruleObj.Remote
				localRule = ruleObj.Local
			case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp:
				remoteRule = ruleObj.Remote
				localRule = ruleObj.Local

			default:
				return nil, fmt.Errorf("SG %s has unsupported type for the %dth rule", *sgObj.Name, i)
			}
			var localCidrsOrAddresses, remoteCidrsOrAddresses []*string
			if localRule != nil {
				local := localRule.(*vpc1.SecurityGroupRuleLocal)
				localCidrsOrAddresses = []*string{local.Address, local.CIDRBlock}
			}
			if remoteRule != nil {
				remote := remoteRule.(*vpc1.SecurityGroupRuleRemote)
				// we also might have remote.name, in such case we need to refer to addresses of the sg members.
				// (in this stage we do not have the sg members yet).
				// however, the members are resources, and their addresses are already reserved IP.
				// do these blocks are already fullyReservedBlocks we can ignore them:
				remoteCidrsOrAddresses = []*string{remote.Address, remote.CIDRBlock}
			}
			if _, ok := cidrs[*sgObj.VPC.CRN]; !ok {
				cidrs[*sgObj.VPC.CRN] = []*string{}
			}
			cidrs[*sgObj.VPC.CRN] = append(cidrs[*sgObj.VPC.CRN], localCidrsOrAddresses...)
			cidrs[*sgObj.VPC.CRN] = append(cidrs[*sgObj.VPC.CRN], remoteCidrsOrAddresses...)
		}
	}
	return cidrs, nil
}

// getSubnetsBlocks() gets the subnets blocks to be used for creating private IPs
// it collects the rules cidrs and use them to get the subnets block.
func getSubnetsBlocks(rc *IBMresourcesContainer,
	skipByVPC map[string]bool) (subnetsBlocks subnetsIPBlocks, err error) {
	naclCidrs, err := getACLRulesCidrs(rc, skipByVPC)
	if err != nil {
		return nil, err
	}
	sgCidrs, err := getGSRulesCidrs(rc, skipByVPC)
	if err != nil {
		return nil, err
	}
	return getSubnetsIPBlocks(rc, []map[string][]*string{naclCidrs, sgCidrs}, skipByVPC)
}
