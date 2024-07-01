/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package vpcmodel

import (
	"fmt"
	"slices"
	"sort"

	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/models/pkg/ipblock"
)

// ///////////////////////////////////////////////////////////////////////
// connection from and to load balancer are done via private IPs
// created to it upon its deployment.
// However, when a load balancer is deployed,
// Private IPs are not created for all the load balancer subnets.
// To understand and monitor the connectivity that is potentially induced by the load balancer,
// we create a private IP for all the load balancer subnets.
// (we calls these private IPs fake private Ips)
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
//   2. allocate a free address for the fake private IPs - to this end, we hold for each subnet freeAddressesBlocks,
//      freeAddressesBlocks are splitByFiltersBlocks minus all the addresses that were already allocated.
//      to get freeAddressesBlocks, we first copy splitByFiltersBlocks, then we remove the subnet already allocated addresses.
//      (we get these addresses from the subnet reserved IP).
//       when a free address is needed, we take the first address of the block and remove it from the free blocks list.

// /////////////////////////////////////////////////////////////////////////////////////////
// oneSubnetBlocks hold the blocks of one subnet
type oneSubnetBlocks struct {
	subnetOriginalBlock *ipblock.IPBlock // the block of the cidr of the subnet
	// splitByFiltersBlocks are the atomic blocks induced by the filters, the union of this slice is the subnetOriginalBlock
	splitByFiltersBlocks []*ipblock.IPBlock
	// freeAddressesBlocks are the splitByFiltersBlocks minus the reserved IPs
	// each block in splitByFiltersBlocks has a corresponding block at freeAddressesBlocks
	freeAddressesBlocks []*ipblock.IPBlock
	// fullyReservedBlocks is a bool per block.
	// its true if all the addresses in the original block are reserved IP
	// for these blocks there is no need to create private IPs
	fullyReservedBlocks []bool
}

// SubnetsIPBlocks is a map from the subnet crn to the subnets block
type SubnetsIPBlocks map[string]*oneSubnetBlocks

// getSubnetsIPBlocks() is the main func that creates the subnetsBlocks, steps:
// 1. get the subnets original blocks
// 2. calculate the filters blocks
// 3. calculate the splitByFiltersBlocks
// 4. calculate the freeAddressesBlocks
func GetSubnetsIPBlocks(rc *datamodel.ResourcesContainerModel,
	filtersCidrs []map[string][]*string) (subnetsBlocks SubnetsIPBlocks, err error) {
	subnetsBlocks = SubnetsIPBlocks{}
	// gets the original blocks of the subnets:
	if err := subnetsBlocks.getSubnetsOriginalBlocks(rc); err != nil {
		return nil, err
	}
	// calc the filters blocks:
	filtersBlocks, err := getFiltersBlocks(filtersCidrs)
	if err != nil {
		return nil, err
	}
	// calc the splitByFiltersBlocks:
	subnetsBlocks.splitSubnetsOriginalBlocks(rc, filtersBlocks)
	// calc the freeAddressesBlocks:
	if err := subnetsBlocks.getSubnetsFreeBlocks(rc); err != nil {
		return nil, err
	}
	return subnetsBlocks, nil
}

func (subnetsBlocks SubnetsIPBlocks) getSubnetsOriginalBlocks(rc *datamodel.ResourcesContainerModel) (err error) {
	for _, subnetObj := range rc.SubnetList {
		subnetsBlocks[*subnetObj.CRN] = &oneSubnetBlocks{}
		subnetsBlocks[*subnetObj.CRN].subnetOriginalBlock, err = ipblock.FromCidr(*subnetObj.Ipv4CIDRBlock)
		if err != nil {
			return err
		}
	}
	return nil
}

// splitSubnetsOriginalBlocks() splits the subnet's cidr(s) to (maximal) disjoint blocks -
// such that each block is atomic w.r.t. the filters rules
func (subnetsBlocks SubnetsIPBlocks) splitSubnetsOriginalBlocks(rc *datamodel.ResourcesContainerModel, filtersBlocks filtersBlocks) {
	for _, subnetObj := range rc.SubnetList {
		subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks =
			splitSubnetOriginalBlock(subnetsBlocks[*subnetObj.CRN].subnetOriginalBlock, filtersBlocks[*subnetObj.VPC.CRN])
	}
}

// splitSubnetsOriginalBlocks() splits one subnet's cidr(s) to (maximal) disjoint blocks -
// such that each block is atomic w.r.t. the filters rules
func splitSubnetOriginalBlock(subnetOriginalBlock *ipblock.IPBlock, filtersBlocks []*ipblock.IPBlock) []*ipblock.IPBlock {
	filtersBlocksOnSubnet := []*ipblock.IPBlock{}
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
func (subnetsBlocks SubnetsIPBlocks) getSubnetsFreeBlocks(rc *datamodel.ResourcesContainerModel) error {
	for _, subnetObj := range rc.SubnetList {
		subnetsBlocks[*subnetObj.CRN].freeAddressesBlocks = make([]*ipblock.IPBlock, len(subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks))
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
func (subnetsBlocks SubnetsIPBlocks) AllocSubnetFreeAddress(subnetCRN string, blockIndex int) (string, error) {
	if subnetsBlocks[subnetCRN].freeAddressesBlocks[blockIndex].IsEmpty() {
		return "", fmt.Errorf("fail to allocate a free address at block: %s ", subnetsBlocks[subnetCRN].freeAddressesBlocks[blockIndex].String())
	}
	address := subnetsBlocks[subnetCRN].freeAddressesBlocks[blockIndex].FirstIPAddress()
	return address, subnetsBlocks.removeAddressFromFree(address, subnetCRN, blockIndex)
}
func (subnetsBlocks SubnetsIPBlocks) SubnetBlocks(subnetCRN string) []*ipblock.IPBlock {
	return subnetsBlocks[subnetCRN].splitByFiltersBlocks
}
func (subnetsBlocks SubnetsIPBlocks) IsFullyReservedBlock(subnetCRN string, blockIndex int) bool {
	return subnetsBlocks[subnetCRN].fullyReservedBlocks[blockIndex]
}

func (subnetsBlocks SubnetsIPBlocks) removeAddressFromFree(address, subnetCRN string, blockIndex int) error {
	addressBlock, err := ipblock.FromIPAddress(address)
	if err != nil {
		return err
	}
	subnetsBlocks[subnetCRN].freeAddressesBlocks[blockIndex] =
		subnetsBlocks[subnetCRN].freeAddressesBlocks[blockIndex].Subtract(addressBlock)
	return nil
}

// filtersBlocks is a map from VPC UID to a list of IPBlocks,
// which holds the list of disjoint IPBlocks computed from all referenced CIDRs in that VPC's filters rules
type filtersBlocks map[string][]*ipblock.IPBlock

// ///////////////////////////////////////////
// getFiltersBlocks() create a slice of disjoint blocks for each vpc, split according to the rules blocks, and their sum is allCidr:
func getFiltersBlocks(filtersCidrs []map[string][]*string) (blocks filtersBlocks, err error) {
	// sorting by vpc:
	vpcCidrs := getVpcsCidrs(filtersCidrs)
	// disjointing:
	return disjointVpcCidrs(vpcCidrs)
}

// getVpcsCidrs() sort the cidr of all filters for each vpc separately, adding ipblock.CidrAll for every vpc
func getVpcsCidrs(filtersCidrs []map[string][]*string) map[string][]string {
	vpcCidrs := map[string][]string{}
	for _, filterCidrsOrAddresses := range filtersCidrs {
		for vpc, vpcCidrsOrAddresses := range filterCidrsOrAddresses {
			if _, ok := vpcCidrs[vpc]; !ok {
				vpcCidrs[vpc] = []string{ipblock.CidrAll}
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
func disjointCidrs(cidrs []string) ([]*ipblock.IPBlock, error) {
	compactCidrs := slices.Compact(cidrs)
	cidrBlocks := make([]*ipblock.IPBlock, len(compactCidrs))
	for i, cidr := range compactCidrs {
		block, err := ipblock.FromCidrOrAddress(cidr)
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
	unionOfPreviousBlocks := ipblock.New()
	disjointBlocks := []*ipblock.IPBlock{}
	for _, b := range cidrBlocks {
		newBlock := b.Subtract(unionOfPreviousBlocks)
		if !newBlock.IsEmpty() {
			disjointBlocks = append(disjointBlocks, newBlock)
		}
		unionOfPreviousBlocks = unionOfPreviousBlocks.Union(b)
	}
	return disjointBlocks, nil
}
