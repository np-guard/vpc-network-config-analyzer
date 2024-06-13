/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package ibmvpc

import (
	"fmt"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

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
// subnetIPBlocks hold the blocks of a subnet
type subnetIPBlocks struct {
	subnetOriginalBlock  *ipblock.IPBlock // the block of the original cidr of the subnet
	splitByFiltersBlocks []*ipblock.IPBlock
	freeAddressesBlocks  []*ipblock.IPBlock // each block in splitByFiltersBlocks has a corresponding block at freeAddressesBlocks
	fullyReservedBlocks  []bool             // true if all the addresses in the block are reserved IP
}
type subnetsIPBlocks map[string]*subnetIPBlocks

func getSubnetsIPBlocks(rc *datamodel.ResourcesContainerModel) (subnetsBlocks subnetsIPBlocks, err error) {
	subnetsBlocks = subnetsIPBlocks{}
	// get all the original blocks of the subnets:
	if err := subnetsBlocks.getSubnetsOriginalBlocks(rc); err != nil {
		return nil, err
	}
	// calc the filters blocks:
	filtersBlocks, err := getFiltersBlocks(rc)
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

func (subnetsBlocks subnetsIPBlocks) getSubnetsOriginalBlocks(rc *datamodel.ResourcesContainerModel) (err error) {
	for _, subnetObj := range rc.SubnetList {
		subnetsBlocks[*subnetObj.CRN] = &subnetIPBlocks{}
		subnetsBlocks[*subnetObj.CRN].subnetOriginalBlock, err = ipblock.FromCidr(*subnetObj.Ipv4CIDRBlock)
		if err != nil {
			return err
		}
	}
	return nil
}

// splitSubnetsOriginalBlocks():
// the goal of this func is to split the original subnet cidr to disjoint blocks, according to the filters blocks:
// for each subnet it gets all the blocks that intersect with subnet original block
func (subnetsBlocks subnetsIPBlocks) splitSubnetsOriginalBlocks(rc *datamodel.ResourcesContainerModel, filtersBlocks filtersBlocks) {
	for _, subnetObj := range rc.SubnetList {
		subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks =
			splitSubnetOriginalBlock(subnetsBlocks[*subnetObj.CRN].subnetOriginalBlock, filtersBlocks[*subnetObj.VPC.CRN])
	}
}

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

// getSubnetsFreeBlocks() - calc all the addresses that are not allocated:
// for each subnet:
//  1. make a copy of the splitByFiltersBlocks
//  2. remove the addresses that was already allocated
func (subnetsBlocks subnetsIPBlocks) getSubnetsFreeBlocks(rc *datamodel.ResourcesContainerModel) error {
	for _, subnetObj := range rc.SubnetList {
		subnetsBlocks[*subnetObj.CRN].freeAddressesBlocks = make([]*ipblock.IPBlock, len(subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks))
		subnetsBlocks[*subnetObj.CRN].fullyReservedBlocks = make([]bool, len(subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks))
		for blockIndex, b := range subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks {
			subnetsBlocks[*subnetObj.CRN].freeAddressesBlocks[blockIndex] = b.Copy()
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
func (subnetsBlocks subnetsIPBlocks) subnetBlocks(subnetCRN string) []*ipblock.IPBlock {
	return subnetsBlocks[subnetCRN].splitByFiltersBlocks
}
func (subnetsBlocks subnetsIPBlocks) isFullyReservedBlock(subnetCRN string, blockIndex int) bool {
	return subnetsBlocks[subnetCRN].fullyReservedBlocks[blockIndex]
}

func (subnetsBlocks subnetsIPBlocks) removeAddressFromFree(address, subnetCRN string, blockIndex int) error {
	addressBlock, err := ipblock.FromIPAddress(address)
	if err != nil {
		return err
	}
	subnetsBlocks[subnetCRN].freeAddressesBlocks[blockIndex] =
		subnetsBlocks[subnetCRN].freeAddressesBlocks[blockIndex].Subtract(addressBlock)
	return nil
}

// ///////////////////////////////////////////
// filtersBlocks create a slice of disjoint blocks, split according to the rules blocks, and their sum is allCidr:
// 1. collect a slice all the acl blocks
// 2. add to the slice all the gs blocks
// 3. add to the slice the CidrAll block
// 3. create a list of disjoint blocks from this slice
type filtersBlocks map[string][]*ipblock.IPBlock

func getFiltersBlocks(rc *datamodel.ResourcesContainerModel) (filtersBlocks, error) {
	blocks := filtersBlocks{}
	if err := blocks.addACLRuleBlocks(rc); err != nil {
		return nil, err
	}
	if err := blocks.addSGRulesBlocks(rc); err != nil {
		return nil, err
	}
	blocks.disjointBlocks()
	return blocks, nil
}

func (blocks filtersBlocks) disjointBlocks() {
	for vpc := range blocks {
		blocks[vpc] = ipblock.DisjointIPBlocks(blocks[vpc], []*ipblock.IPBlock{ipblock.GetCidrAll()})
	}
}

func (blocks filtersBlocks) addACLRuleBlocks(rc *datamodel.ResourcesContainerModel) error {
	for _, aclObj := range rc.NetworkACLList {
		for _, rule := range aclObj.Rules {
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
				return fmt.Errorf("ACL has unsupported type for rule: %s ", *aclObj.Name)
			}
			if err := blocks.addBlocks(*aclObj.VPC.CRN, []*string{src, dst}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (blocks filtersBlocks) addSGRulesBlocks(rc *datamodel.ResourcesContainerModel) error {
	for _, sgObj := range rc.SecurityGroupList {
		for _, rule := range sgObj.Rules {
			var remote *vpc1.SecurityGroupRuleRemote
			var local *vpc1.SecurityGroupRuleLocal
			switch ruleObj := rule.(type) {
			case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolAll:
				remote = ruleObj.Remote.(*vpc1.SecurityGroupRuleRemote)
				local = ruleObj.Local.(*vpc1.SecurityGroupRuleLocal)
			case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp:
				remote = ruleObj.Remote.(*vpc1.SecurityGroupRuleRemote)
				local = ruleObj.Local.(*vpc1.SecurityGroupRuleLocal)
			case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp:
				remote = ruleObj.Remote.(*vpc1.SecurityGroupRuleRemote)
				local = ruleObj.Local.(*vpc1.SecurityGroupRuleLocal)
			default:
				return fmt.Errorf("SG has unsupported type for rule: %s ", *sgObj.Name)
			}
			// we also have remote.name. however, these are reference to other sg, so we can ignore them:
			if err := blocks.addBlocks(*sgObj.VPC.CRN, []*string{remote.Address, remote.CIDRBlock, local.Address, local.CIDRBlock}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (blocks filtersBlocks) addBlocks(vpc string, cidrsOrAddresses []*string) error {
	if _, ok := blocks[vpc]; !ok {
		blocks[vpc] = []*ipblock.IPBlock{}
	}
	for _, cidrOrAddress := range cidrsOrAddresses {
		if cidrOrAddress != nil {
			b, err := ipblock.FromCidrOrAddress(*cidrOrAddress)
			if err != nil {
				return err
			}
			blocks[vpc] = append(blocks[vpc], b)
		}
	}
	return nil
}
