package ibmvpc

import (
	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/models/pkg/ipblock"
)

// ///////////////////////////////////////////////////////////////////////
// when a load balancer is deployed, Private IPs are not created in all the load balancer subnets.
// however, we want to create a private IP for all of the load balancer subnets.
// (we calls these private IPs fake private Ips)
// More that that, when a filter rule split the subnet cidr to blocks, we want to create private ip per block.

// to create a private IP which does not exist in the config, we need an unused address.
// subnetsIPBlocks has two main purposes:
// 1. for each subnet - calculate the blocks that the subnet cidr was split to
// 2. allocate a free address for the fake private IPs
//

// /////////////////////////////////////////////////////////////////////////////////////////
// subnetIPBlocks holds the block of a subnet
type subnetIPBlocks struct {
	subnetOriginalBlock *ipblock.IPBlock // the block of the original cidr of the subnet
	// splitByFiltersBlocks - the blocks that  created when all filters rules split the original cidr
	// splitByFiltersBlocks are disjoint to each other, and their sum is the original cidr
	splitByFiltersBlocks []*ipblock.IPBlock
	// freeAddressesBlocks - these are splitByFiltersBlocks minus the already used address
	// each block in splitByFiltersBlocks has a corresponding block at freeAddressesBlocks
	freeAddressesBlocks []*ipblock.IPBlock
}
type subnetsIPBlocks map[string]*subnetIPBlocks

// getSubnetsIPBlocks()
func getSubnetsIPBlocks(rc *datamodel.ResourcesContainerModel) (subnetsBlocks subnetsIPBlocks, err error) {
	subnetsBlocks = subnetsIPBlocks{}
	// get all the original blocks of the subnets:
	if err = subnetsBlocks.getSubnetsOriginalBlocks(rc); err != nil {
		return nil, err
	}
	// calc the splitByFiltersBlocks:
	if err = subnetsBlocks.splitSubnetsOriginalBlocks(rc); err != nil {
		return nil, err
	}
	// calc the freeAddressesBlocks:
	if err = subnetsBlocks.getSubnetsFreeBlocks(rc); err != nil {
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
// steps:
//  1. split the allCidr to disjoint blocks by the filters rules.
//  2. for each subnet:
//     a. for each filter block that intersect with subnet original block, collect the intersection to a slice
//     b. add the original block ot this slice
//     c. create a disjoint slice from this slice
func (subnetsBlocks subnetsIPBlocks) splitSubnetsOriginalBlocks(rc *datamodel.ResourcesContainerModel) error {
	filtersBlocks, err := getFiltersBlocks(rc)
	if err != nil {
		return err
	}
	for _, subnetObj := range rc.SubnetList {
		filtersBlocksOnSubnet := []*ipblock.IPBlock{}
		for _, filterBlock := range filtersBlocks[*subnetObj.VPC.CRN] {
			filterBlocksOnSubnet := subnetsBlocks[*subnetObj.CRN].subnetOriginalBlock.Intersect(filterBlock)
			if !filterBlocksOnSubnet.IsEmpty() {
				filtersBlocksOnSubnet = append(filtersBlocksOnSubnet, filterBlocksOnSubnet)
			}
		}
		subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks = ipblock.DisjointIPBlocks(filtersBlocksOnSubnet, []*ipblock.IPBlock{subnetsBlocks[*subnetObj.CRN].subnetOriginalBlock})
	}
	return nil
}

// getSubnetsFreeBlocks() - calc all the addresses that are not allocated:
// for each subnet:
//  1. make a copy of the splitByFiltersBlocks
//  2. remove the addresses that was already allocated
func (subnetsBlocks subnetsIPBlocks) getSubnetsFreeBlocks(rc *datamodel.ResourcesContainerModel) error {
	for _, subnetObj := range rc.SubnetList {
		subnetsBlocks[*subnetObj.CRN].freeAddressesBlocks = make([]*ipblock.IPBlock, len(subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks))
		for i, b := range subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks {
			subnetsBlocks[*subnetObj.CRN].freeAddressesBlocks[i] = b.Copy()
		}
		// all the allocated IPs are at subnetObj.ReservedIps.
		for blockIndex := range subnetsBlocks[*subnetObj.CRN].splitByFiltersBlocks {
			for _, reservedIP := range subnetObj.ReservedIps {
				if err := subnetsBlocks.removeAddressFromFree(*reservedIP.Address, *subnetObj.CRN, blockIndex); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// allocSubnetFreeAddress() allocated a free address from a block (for the private ip):
func (subnetsBlocks subnetsIPBlocks) allocSubnetFreeAddress(subnetCRN string, blockIndex int) (string, error) {
	address := subnetsBlocks[subnetCRN].freeAddressesBlocks[blockIndex].FirstIPAddress()
	return address, subnetsBlocks.removeAddressFromFree(address, subnetCRN, blockIndex)
}
func (subnetsBlocks subnetsIPBlocks) subnetBlocks(subnetCRN string) []*ipblock.IPBlock {
	return subnetsBlocks[subnetCRN].splitByFiltersBlocks
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
	if err := blocks.addAclRuleBlocks(rc); err != nil {
		return nil, err
	}
	if err := blocks.addSGRulesBlocks(rc); err != nil {
		return nil, err
	}
	for vpc := range blocks {
		blocks[vpc] = ipblock.DisjointIPBlocks(blocks[vpc], []*ipblock.IPBlock{ipblock.GetCidrAll()})
	}
	return blocks, nil
}

func (blocks filtersBlocks) addAclRuleBlocks(rc *datamodel.ResourcesContainerModel) error {
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
			var remote, local *string
			switch ruleObj := rule.(type) {
			case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolAll:
				remote = ruleObj.Remote.(*vpc1.SecurityGroupRuleRemote).CIDRBlock
				local = ruleObj.Local.(*vpc1.SecurityGroupRuleLocal).CIDRBlock
			case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp:
				remote = ruleObj.Remote.(*vpc1.SecurityGroupRuleRemote).CIDRBlock
				local = ruleObj.Local.(*vpc1.SecurityGroupRuleLocal).CIDRBlock
			case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp:
				remote = ruleObj.Remote.(*vpc1.SecurityGroupRuleRemote).CIDRBlock
				local = ruleObj.Local.(*vpc1.SecurityGroupRuleLocal).CIDRBlock
			}
			if err := blocks.addBlocks(*sgObj.VPC.CRN, []*string{remote, local}); err != nil {
				return err
			}

		}
	}
	return nil
}

func (blocks filtersBlocks) addBlocks(vpc string, cidrs []*string) error {
	if _, ok := blocks[vpc]; !ok {
		blocks[vpc] = []*ipblock.IPBlock{}
	}
	for _, cidr := range cidrs {
		if cidr != nil {
			b, err := ipblock.FromCidr(*cidr)
			if err != nil {
				return err
			}
			blocks[vpc] = append(blocks[vpc], b)
		}
	}
	return nil
}
