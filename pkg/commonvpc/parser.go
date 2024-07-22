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
	ProtocolTCP  = "tcp"
	AllProtocols = "-1"
	ProtocolUDP  = "udp"
	ProtocolICMP = "icmp"
	Inbound      = "inbound"
	Outbound     = "outbound"
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

type ResourcesContainer interface {
	VpcConfigsFromFiles(fileNames []string, vpcID, resourceGroup string, regions []string) (
		*vpcmodel.MultipleVPCConfigs, error)
	VPCConfigsFromResources(vpcID, resourceGroup string, regions []string) (
		*vpcmodel.MultipleVPCConfigs, error)
	ParseResourcesFromFile(fileName string) error
}

func NewNetworkInterface(name, uid, zone, address, vsi string, vpc vpcmodel.VPCResourceIntf) (*NetworkInterface, error) {
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
		Vsi: vsi,
	}

	if err := intfNode.SetIPBlockFromAddress(); err != nil {
		return nil, err
	}
	return intfNode, nil
}

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

func UpdateConfigWithSubnet(name, uid, zone, cidr, vpcUID string, res *vpcmodel.MultipleVPCConfigs,
	vpcInternalAddressRange map[string]*ipblock.IPBlock,
	subnetNameToNetIntf map[string][]*NetworkInterface) (*Subnet, error) {
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
	if subnetInterfaces, ok := subnetNameToNetIntf[name]; ok {
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

func NewSGResource(name, uid string, vpc vpcmodel.VPC, analyzer SpecificSGAnalyzer,
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
	sgMap[vpc.UID()][name] = sgResource
	sgLists[vpc.UID()] = append(sgLists[vpc.UID()], sgResource)
	return sgResource
}

func UpdateVPCSAddressRanges(vpcInternalAddressRange map[string]*ipblock.IPBlock,
	vpcsMap *vpcmodel.MultipleVPCConfigs) error {
	// assign to each vpc object its internal address range, as inferred from its subnets
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

func NewEmptyVPCConfig() *vpcmodel.VPCConfig {
	return &vpcmodel.VPCConfig{
		UIDToResource: map[string]vpcmodel.VPCResourceIntf{},
	}
}

func GetRegionByName(regionName string, regionToStructMap map[string]*Region) *Region {
	regionPointer, ok := regionToStructMap[regionName]

	if !ok {
		regionToStructMap[regionName] = &Region{Name: regionName}
		return regionToStructMap[regionName]
	}
	return regionPointer
}

func NewVPC(name, uid, region string, zonesToAP map[string][]string, regionToStructMap map[string]*Region) (
	vpcNodeSet *VPC, err error) {
	var regionPointer *Region
	if regionToStructMap != nil {
		regionPointer = GetRegionByName(region, regionToStructMap)
	}
	vpcNodeSet = &VPC{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: name,
			ResourceUID:  uid,
			ResourceType: ResourceTypeVPC,
			Region:       region,
		},
		Zones:     map[string]*Zone{},
		VPCregion: regionPointer,
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

func GetVPCconfigByUID(res *vpcmodel.MultipleVPCConfigs, uid string) (*vpcmodel.VPCConfig, error) {
	vpcConfig, ok := res.Configs()[uid]
	if !ok {
		return nil, fmt.Errorf("missing VPC resource of uid %s", uid)
	}
	return vpcConfig, nil
}

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
	logging.Debugf(strings.Repeat("-", lineSectionLen))
}

func PrintSGRules(sg *SecurityGroup) {
	numRules := sg.Analyzer.SgAnalyzer.GetNumberOfRules()
	logging.Debugf("num rules: %d\n", numRules)
	if sg.Members != nil {
		keys := make([]string, 0, len(sg.Members))
		for k := range sg.Members {
			keys = append(keys, k)
		}
		logging.Debugf("members: " + strings.Join(keys, ", "))
	}
	for i := 0; i < numRules; i++ {
		strRule, _, _, err := sg.Analyzer.SgAnalyzer.GetSGRule(i)
		PrintRule(strRule, i, err)
	}
}

func PrintRule(ruleStr string, index int, err error) {
	if err == nil {
		logging.Debugf(ruleStr)
	} else {
		logging.Debugf("err for rule %d: %s\n", index, err.Error())
	}
}