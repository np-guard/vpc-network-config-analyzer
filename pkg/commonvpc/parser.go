/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commonvpc

import (
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/logging"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const (
	Inbound  = "inbound"
	Outbound = "outbound"
	// used as the type within api objects (e.g. SecurityGroup.Targets.ResourceType)
	NetworkInterfaceResourceType = "network_interface"
	VpeResourceType              = "endpoint_gateway"
	LoadBalancerResourceType     = "load_balancer"
	// iksNodeResourceType is not actually used from input api objects, but is added by the parser to SGs with targets
	// that should be added with iks nodes
	IksNodeResourceType = "iks_node" // used as the type within api objects (e.g. SecurityGroup.Targets.ResourceType)
	lineSectionLen      = 41
)

// Resource types const strings, used in the generated resources of this pkg
const (
	ResourceTypeVSI              = "VSI"
	ResourceTypeNetworkInterface = "NetworkInterface"
	ResourceTypeSubnet           = "Subnet"
	ResourceTypePublicGateway    = "PublicGateway"
	ResourceTypeInternetGateway  = "InternetGateway"
	ResourceTypeFloatingIP       = "FloatingIP"
	ResourceTypeVPC              = "VPC"
	ResourceTypeSG               = "SG"
	ResourceTypeNACL             = "NACL"
	ResourceTypeIKSNode          = "IKSNodeNetworkInterface"
	ResourceTypeVPE              = "VPE"
	ResourceTypeTGW              = "TGW"
	ResourceTypeReservedIP       = "ReservedIP"
	ResourceTypeLoadBalancer     = "LoadBalancer"
	ResourceTypePrivateIP        = "PrivateIP"
	ResourceTypeRoutingTable     = "RoutingTable"
)

// Implemented by AWSresourcesContainer and IBMresourcesContainer
type ResourcesContainer interface {
	VpcConfigsFromFiles(fileNames []string, vpcID, resourceGroup string, regions []string) (
		*vpcmodel.MultipleVPCConfigs, error)
	VPCConfigsFromResources(vpcID, resourceGroup string, regions []string) (
		*vpcmodel.MultipleVPCConfigs, error)
	ParseResourcesFromFile(fileName string) error
}

// NewNetworkInterface gets NetworkInterface properties and returns NetworkInterface object
func NewNetworkInterface(name, uid, zone, address, vsi string, numberOfNifs int, vpc vpcmodel.VPCResourceIntf) (*NetworkInterface, error) {
	intfNode := &NetworkInterface{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: name,
			ResourceUID:  uid,
			ResourceType: ResourceTypeNetworkInterface,
			Zone:         zone,
			VPCRef:       vpc,
			Region:       vpc.RegionName(),
		},
		InternalNode: vpcmodel.InternalNode{
			AddressStr: address,
		},
		Vsi:               vsi,
		numberOfNifsInVsi: numberOfNifs,
	}

	if err := intfNode.SetIPBlockFromAddress(); err != nil {
		return nil, err
	}
	return intfNode, nil
}

// NewVSI gets NetworkInterface properties and returns Vsi object
func NewVSI(name, uid, zone string, vpc vpcmodel.VPCResourceIntf, res *vpcmodel.MultipleVPCConfigs) (*Vsi, error) {
	vsiNode := &Vsi{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: name,
			ResourceUID:  uid,
			Zone:         zone,
			ResourceType: ResourceTypeVSI,
			VPCRef:       vpc,
			Region:       vpc.RegionName(),
		},
		VPCnodes: []vpcmodel.Node{},
	}

	if err := AddZone(zone, vpc.UID(), res); err != nil {
		return nil, err
	}
	return vsiNode, nil
}

// UpdateConfigWithSubnet creates new subnets from provided args and update it's vpc object and subnets list
func UpdateConfigWithSubnet(name, uid, zone, cidr, vpcUID string, res *vpcmodel.MultipleVPCConfigs,
	vpcInternalAddressRange map[string]*ipblock.IPBlock,
	subnetIDToNetIntf map[string][]*NetworkInterface) (*Subnet, error) {
	subnetNodes := []vpcmodel.Node{}
	vpc, err := GetVPCObjectByUID(res, vpcUID)
	if err != nil {
		return nil, err
	}

	subnetNode, err := NewSubnet(name, uid, zone, cidr, vpc)
	if err != nil {
		return nil, err
	}
	if vpcInternalAddressRange[vpcUID] == nil {
		vpcInternalAddressRange[vpcUID] = subnetNode.IPblock
	} else {
		vpcInternalAddressRange[vpcUID] = vpcInternalAddressRange[vpcUID].Union(subnetNode.IPblock)
	}
	res.Config(vpcUID).Subnets = append(res.Config(vpcUID).Subnets, subnetNode)
	if err := AddZone(zone, vpcUID, res); err != nil {
		return nil, err
	}
	res.Config(vpcUID).UIDToResource[subnetNode.ResourceUID] = subnetNode

	// add pointers from networkInterface to its subnet, given the current subnet created
	if subnetInterfaces, ok := subnetIDToNetIntf[uid]; ok {
		for _, netIntf := range subnetInterfaces {
			netIntf.SubnetResource = subnetNode
			subnetNodes = append(subnetNodes, netIntf)
		}
		subnetNode.VPCnodes = subnetNodes
	}
	// add subnet to its vpc's list of subnets
	vpc.SubnetsList = append(vpc.SubnetsList, subnetNode)
	return subnetNode, nil
}

// pairingID is the identifier for the sgs, in ibm it is the name of the sg, and in aws it is groupID
// it is used later in sg analysis
func NewSGResource(name, uid, pairingID string, vpc vpcmodel.VPC, analyzer SpecificSGAnalyzer,
	sgMap map[string]map[string]*SecurityGroup,
	sgLists map[string][]*SecurityGroup) *SecurityGroup {
	sgResource := &SecurityGroup{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: name,
			ResourceUID:  uid,
			ResourceType: ResourceTypeSG,
			VPCRef:       vpc,
			Region:       vpc.RegionName(),
		},
		Analyzer: NewSGAnalyzer(analyzer), Members: map[string]vpcmodel.Node{},
	}
	if _, ok := sgMap[vpc.UID()]; !ok {
		sgMap[vpc.UID()] = map[string]*SecurityGroup{}
	}
	sgMap[vpc.UID()][pairingID] = sgResource
	sgLists[vpc.UID()] = append(sgLists[vpc.UID()], sgResource)
	return sgResource
}

// UpdateVPCSAddressRanges assigns to each vpc object its internal address range, as inferred from its subnets
func UpdateVPCSAddressRanges(vpcInternalAddressRange map[string]*ipblock.IPBlock,
	vpcsMap *vpcmodel.MultipleVPCConfigs) error {
	for vpcUID, addressRange := range vpcInternalAddressRange {
		var vpc *VPC
		vpc, err := GetVPCObjectByUID(vpcsMap, vpcUID)
		if err != nil {
			return err
		}
		vpc.InternalAddressRange = addressRange
	}
	return nil
}

// NewEmptyVPCConfig returns a new empty vpc config
func NewEmptyVPCConfig() *vpcmodel.VPCConfig {
	return &vpcmodel.VPCConfig{
		UIDToResource: map[string]vpcmodel.VPCResourceIntf{},
	}
}

// GetRegionByName returns pointer to the supported name from regionToStructMap
// if the region is not in the map, create new one
func GetRegionByName(regionName string, regionToStructMap map[string]*Region) *Region {
	regionPointer, ok := regionToStructMap[regionName]

	if !ok {
		regionToStructMap[regionName] = &Region{Name: regionName}
		return regionToStructMap[regionName]
	}
	return regionPointer
}

// NewVPC gets NetworkInterface properties and returns VPC object
func NewVPC(name, uid, region string, zonesToAP map[string][]string, regionToStructMap map[string]*Region) (
	vpcNodeSet *VPC, err error) {
	vpcNodeSet = &VPC{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: name,
			ResourceUID:  uid,
			ResourceType: ResourceTypeVPC,
			Region:       region,
		},
		Zones:     map[string]*Zone{},
		VPCregion: GetRegionByName(region, regionToStructMap),
		VPCnodes:  []vpcmodel.Node{},
	}
	for zoneName, zoneCidrsList := range zonesToAP {
		vpcNodeSet.AddressPrefixesList = append(vpcNodeSet.AddressPrefixesList, zoneCidrsList...)
		zoneIPBlock, err := ipblock.FromCidrList(zoneCidrsList)
		if err != nil {
			return nil, err
		}
		vpcNodeSet.Zones[zoneName] = &Zone{Name: zoneName,
			Vpc:     vpcNodeSet,
			Cidrs:   zoneCidrsList,
			IPblock: zoneIPBlock}
	}

	vpcNodeSet.AddressPrefixesIPBlock, err = ipblock.FromCidrList(vpcNodeSet.AddressPrefixesList)
	if err != nil {
		return nil, err
	}
	vpcNodeSet.VPCRef = vpcNodeSet
	return vpcNodeSet, nil
}

// GetVPCObjectByUID gets vpc uid and returns it's config
func GetVPCconfigByUID(res *vpcmodel.MultipleVPCConfigs, uid string) (*vpcmodel.VPCConfig, error) {
	vpcConfig, ok := res.Configs()[uid]
	if !ok {
		return nil, fmt.Errorf("missing VPC resource of uid %s", uid)
	}
	return vpcConfig, nil
}

// GetVPCObjectByUID gets vpc uid and returns it's object
func GetVPCObjectByUID(res *vpcmodel.MultipleVPCConfigs, uid string) (*VPC, error) {
	vpcConfig, err := GetVPCconfigByUID(res, uid)
	if err != nil {
		return nil, err
	}
	vpc, ok := vpcConfig.VPC.(*VPC)
	if !ok {
		return nil, fmt.Errorf("VPC missing from config of VPCConfig with uid %s", uid)
	}
	return vpc, nil
}

// AddZone add new zone to supported vpc config by it's uid
func AddZone(zoneName, vpcUID string, res *vpcmodel.MultipleVPCConfigs) error {
	vpc, err := GetVPCObjectByUID(res, vpcUID)
	if err != nil {
		return err
	}
	if _, ok := vpc.Zones[zoneName]; !ok {
		vpc.Zones[zoneName] = &Zone{Name: zoneName, Vpc: vpc}
	}
	return nil
}

// NewSubnet gets NetworkInterface properties and returns Subnet object
func NewSubnet(name, uid, zone, cidr string, vpc vpcmodel.VPCResourceIntf) (*Subnet, error) {
	subnetNode := &Subnet{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: name,
			ResourceUID:  uid,
			Zone:         zone,
			ResourceType: ResourceTypeSubnet,
			VPCRef:       vpc,
			Region:       vpc.RegionName(),
		},
		Cidr: cidr,
	}

	cidrIPBlock, err := ipblock.FromCidr(subnetNode.Cidr)
	if err != nil {
		return nil, err
	}
	subnetNode.IPblock = cidrIPBlock
	return subnetNode, nil
}

func PrintLineSection() {
	logging.Debug(strings.Repeat("-", lineSectionLen))
}

func PrintSGRules(sg *SecurityGroup) {
	numRules := sg.Analyzer.SgAnalyzer.GetNumberOfRules()
	logging.Debugf("num rules: %d\n", numRules)
	if sg.Members != nil {
		keys := make([]string, 0, len(sg.Members))
		for k := range sg.Members {
			keys = append(keys, k)
		}
		logging.Debugf("members: %s", strings.Join(keys, ", "))
	}
	for i := 0; i < numRules; i++ {
		strRule, _, _, err := sg.Analyzer.SgAnalyzer.GetSGRule(i)
		PrintRule(strRule, i, err)
	}
}

func PrintRule(ruleStr string, index int, err error) {
	if err == nil {
		logging.Debug(ruleStr)
	} else {
		logging.Debugf("err for rule %d: %s\n", index, err.Error())
	}
}

// filter VPCs with empty address ranges, then add for remaining VPCs the external nodes
func FilterVPCSAndAddExternalNodes(vpcInternalAddressRange map[string]*ipblock.IPBlock, res *vpcmodel.MultipleVPCConfigs) error {
	for vpcUID, vpcConfig := range res.Configs() {
		if vpcInternalAddressRange[vpcUID] == nil {
			logging.Warnf("Ignoring VPC %s, no subnets found for this VPC\n", vpcUID)
			res.RemoveConfig(vpcUID)
			continue
		}
		err := handlePublicInternetNodes(vpcConfig, vpcInternalAddressRange[vpcUID])
		if err != nil {
			return err
		}
	}
	return nil
}

func handlePublicInternetNodes(res *vpcmodel.VPCConfig, vpcInternalAddressRange *ipblock.IPBlock) error {
	externalNodes, err := addExternalNodes(res, vpcInternalAddressRange)
	if err != nil {
		return err
	}
	publicInternetNodes := []vpcmodel.Node{}
	for _, node := range externalNodes {
		if node.IsPublicInternet() {
			publicInternetNodes = append(publicInternetNodes, node)
		}
	}
	// update destination of routing resources
	for _, r := range res.RoutingResources {
		r.SetExternalDestinations(publicInternetNodes)
	}
	return nil
}

func addExternalNodes(config *vpcmodel.VPCConfig, vpcInternalAddressRange *ipblock.IPBlock) ([]vpcmodel.Node, error) {
	ipBlocks := []*ipblock.IPBlock{}
	for _, f := range config.FilterResources {
		ipBlocks = append(ipBlocks, f.ReferencedIPblocks()...)
	}

	externalRefIPBlocks := []*ipblock.IPBlock{}
	for _, ipBlock := range ipBlocks {
		if ipBlock.ContainedIn(vpcInternalAddressRange) {
			continue
		}
		externalRefIPBlocks = append(externalRefIPBlocks, ipBlock.Subtract(vpcInternalAddressRange))
	}

	disjointRefExternalIPBlocks := ipblock.DisjointIPBlocks(externalRefIPBlocks, []*ipblock.IPBlock{})

	externalNodes, err := vpcmodel.GetExternalNetworkNodes(disjointRefExternalIPBlocks)
	if err != nil {
		return nil, err
	}
	config.Nodes = append(config.Nodes, externalNodes...)
	for _, n := range externalNodes {
		config.UIDToResource[n.UID()] = n
	}
	return externalNodes, nil
}

func PrintNACLRules(nacl *NACL) {
	numRules := nacl.Analyzer.NaclAnalyzer.GetNumberOfRules()
	for i := 0; i < numRules; i++ {
		strRule, _, _, err := nacl.Analyzer.NaclAnalyzer.GetNACLRule(i)
		PrintRule(strRule, i, err)
	}
}

func GetSubnetsNodes(subnets []*Subnet) []vpcmodel.Node {
	res := []vpcmodel.Node{}
	for _, s := range subnets {
		res = append(res, s.Nodes()...)
	}
	return res
}

// UpdateConfigWithSGAndPrepareAnalyzer updates config with sg layer results
func UpdateConfigWithSG(res *vpcmodel.MultipleVPCConfigs, sgLists map[string][]*SecurityGroup) error {
	for vpcUID, sgListInstance := range sgLists {
		vpc, err := GetVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		sgLayer := &SecurityGroupLayer{
			VPCResource: vpcmodel.VPCResource{
				ResourceType: vpcmodel.SecurityGroupLayer,
				VPCRef:       vpc,
				Region:       vpc.RegionName(),
			},
			SgList: sgListInstance}
		res.Config(vpcUID).FilterResources = append(res.Config(vpcUID).FilterResources, sgLayer)
	}

	return nil
}

// PrepareAnalyzers iterates over all sgs in sgMap to map and analyze it's sg Rules
func PrepareAnalyzers(sgMap map[string]map[string]*SecurityGroup) error {
	for _, vpcSgMap := range sgMap {
		for _, sg := range vpcSgMap {
			err := sg.Analyzer.PrepareAnalyzer(vpcSgMap, sg)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
