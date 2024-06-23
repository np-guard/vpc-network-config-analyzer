/*
Copyright 2024- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/np-guard/cloud-resource-collector/pkg/aws"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/logging"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const (
	protocolTCP                  = "tcp"
	protocolUDP                  = "udp"
	inbound                      = "inbound"
	outbound                     = "outbound"
	networkInterfaceResourceType = "network_interface" // used as the type within api objects (e.g. SecurityGroup.Targets.ResourceType)
	vpeResourceType              = "endpoint_gateway"  // used as the type within api objects (e.g. SecurityGroup.Targets.ResourceType)
	loadBalancerResourceType     = "load_balancer"     // used as the type within api objects (e.g. SecurityGroup.Targets.ResourceType)
	// iksNodeResourceType is not actually used from input api objects, but is added by the parser to SGs with targets
	// that should be added with iks nodes
	iksNodeResourceType = "iks_node" // used as the type within api objects (e.g. SecurityGroup.Targets.ResourceType)
	cidrSeparator       = ", "
	linesSeparator      = "---------------------"
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
)

// ParseResourcesFromFile returns aws.ResourcesContainer object, containing the configured resources structs
// from the input JSON file
func ParseResourcesFromFile(fileName string) (*aws.ResourcesContainer, error) {
	inputConfigContent, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	config := aws.ResourcesContainer{}
	err = json.Unmarshal(inputConfigContent, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func mergeResourcesContainers(rc1, rc2 *aws.ResourcesContainer) (*aws.ResourcesContainer, error) {
	if rc2 == nil && rc1 != nil {
		return rc1, nil
	}
	if rc2 != nil && rc1 == nil {
		return rc2, nil
	}
	if rc2 == nil && rc1 == nil {
		return nil, fmt.Errorf("error merging input vpc resources files")
	}
	rc1.VpcsList = append(rc1.VpcsList, rc2.VpcsList...)
	rc1.SubnetsList = append(rc1.SubnetsList, rc2.SubnetsList...)
	rc1.NetworkACLsList = append(rc1.NetworkACLsList, rc2.NetworkACLsList...)
	rc1.SecurityGroupsList = append(rc1.SecurityGroupsList, rc2.SecurityGroupsList...)
	rc1.InternetGWList = append(rc1.InternetGWList, rc2.InternetGWList...)
	rc1.InstancesList = append(rc1.InstancesList, rc2.InstancesList...)

	return rc1, nil
}

func VpcConfigsFromFiles(fileNames []string, vpcID string, resourceGroup string, regions []string) (
	*vpcmodel.MultipleVPCConfigs, error) {
	var mergedRC *aws.ResourcesContainer
	for _, file := range fileNames {
		rc, err1 := ParseResourcesFromFile(file)
		if err1 != nil {
			return nil, fmt.Errorf("error parsing input vpc resources file: %w", err1)
		}
		mergedRC, err1 = mergeResourcesContainers(mergedRC, rc)
		if err1 != nil {
			return nil, err1
		}
	}
	vpcConfigs, err2 := VPCConfigsFromResources(mergedRC, vpcID, resourceGroup, regions)
	if err2 != nil {
		return nil, fmt.Errorf("error generating cloud config from input vpc resources file: %w", err2)
	}
	return vpcConfigs, nil
}

func filterByVpc(rc *aws.ResourcesContainer, vpcID string) map[string]bool {
	shouldSkipVpcIds := make(map[string]bool)
	for _, vpc := range rc.VpcsList {
		if vpcID != "" && *vpc.VpcId != vpcID {
			shouldSkipVpcIds[*vpc.VpcId] = true
		}
	}
	return shouldSkipVpcIds
}

// VPCConfigsFromResources returns a map from VPC UID (string) to its corresponding VPCConfig object,
// containing the parsed resources in the relevant model objects
//
//nolint:funlen // serial list of commands, no need to spill it
func VPCConfigsFromResources(rc *aws.ResourcesContainer, vpcID, resourceGroup string, regions []string) (
	*vpcmodel.MultipleVPCConfigs, error) {
	res := vpcmodel.NewMultipleVPCConfigs("AWS Cloud") // map from VPC UID to its config
	var err error

	// map to filter resources, if certain VPC, resource-group or region list to analyze is specified,
	// skip resources configured outside that VPC
	shouldSkipVpcIds := filterByVpc(rc, vpcID)

	err = getVPCconfig(rc, res, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}

	var vpcInternalAddressRange map[string]*ipblock.IPBlock // map from vpc name to its internal address range

	subnetNameToNetIntf := map[string][]*NetworkInterface{}
	err = getInstancesConfig(rc, subnetNameToNetIntf, res, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}
	vpcInternalAddressRange, err = getSubnetsConfig(res, subnetNameToNetIntf, rc, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}
	// assign to each vpc object its internal address range, as inferred from its subnets
	err = updateVPCSAddressRanges(vpcInternalAddressRange, res)
	if err != nil {
		return nil, err
	}

	err = getSGconfig(rc, res, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}

	printVPCConfigs(res)

	return res, nil
}

func updateVPCSAddressRanges(vpcInternalAddressRange map[string]*ipblock.IPBlock,
	vpcsMap *vpcmodel.MultipleVPCConfigs) error {
	// assign to each vpc object its internal address range, as inferred from its subnets
	for vpcUID, addressRange := range vpcInternalAddressRange {
		var vpc *VPC
		vpc, err := getVPCObjectByUID(vpcsMap, vpcUID)
		if err != nil {
			return err
		}
		vpc.internalAddressRange = addressRange
	}
	return nil
}

func NewEmptyVPCConfig() *vpcmodel.VPCConfig {
	return &vpcmodel.VPCConfig{
		UIDToResource: map[string]vpcmodel.VPCResourceIntf{},
	}
}

func newVPC(uid string) (vpcNodeSet *VPC, err error) {
	vpcNodeSet = &VPC{
		VPCResource: vpcmodel.VPCResource{
			ResourceUID:  uid,
			ResourceType: ResourceTypeVPC,
		},
		nodes: []vpcmodel.Node{},
		zones: map[string]*Zone{},
	}

	vpcNodeSet.VPCRef = vpcNodeSet
	return vpcNodeSet, nil
}

func getVPCconfig(rc *aws.ResourcesContainer,
	res *vpcmodel.MultipleVPCConfigs,
	skipByVPC map[string]bool) error {
	for _, vpc := range rc.VpcsList {
		if skipByVPC[*vpc.VpcId] {
			continue // skip vpc not specified to analyze
		}

		vpcNodeSet, err := newVPC(*vpc.VpcId)
		if err != nil {
			return err
		}
		newVPCConfig := NewEmptyVPCConfig()
		newVPCConfig.UIDToResource[vpcNodeSet.ResourceUID] = vpcNodeSet
		newVPCConfig.VPC = vpcNodeSet
		res.SetConfig(vpcNodeSet.ResourceUID, newVPCConfig)
	}
	if len(res.Configs()) == 0 {
		return errors.New("could not find any VPC to analyze")
	}
	return nil
}

func getVPCconfigByUID(res *vpcmodel.MultipleVPCConfigs, uid string) (*vpcmodel.VPCConfig, error) {
	vpcConfig, ok := res.Configs()[uid]
	if !ok {
		return nil, fmt.Errorf("missing VPC resource of uid %s", uid)
	}
	return vpcConfig, nil
}

func getVPCObjectByUID(res *vpcmodel.MultipleVPCConfigs, uid string) (*VPC, error) {
	vpcConfig, err := getVPCconfigByUID(res, uid)
	if err != nil {
		return nil, err
	}
	vpc, ok := vpcConfig.VPC.(*VPC)
	if !ok {
		return nil, fmt.Errorf("VPC missing from config of VPCConfig with uid %s", uid)
	}
	return vpc, nil
}

func addZone(zoneName, vpcUID string, res *vpcmodel.MultipleVPCConfigs) error {
	vpc, err := getVPCObjectByUID(res, vpcUID)
	if err != nil {
		return err
	}
	if _, ok := vpc.zones[zoneName]; !ok {
		vpc.zones[zoneName] = &Zone{name: zoneName, vpc: vpc}
	}
	return nil
}

func newNetworkInterface(uid, zone, address, vsi string, vpc vpcmodel.VPCResourceIntf,
	securityGroups []types.GroupIdentifier) (*NetworkInterface, error) {
	intfNode := &NetworkInterface{
		VPCResource: vpcmodel.VPCResource{
			ResourceUID:  uid,
			ResourceType: ResourceTypeNetworkInterface,
			Zone:         zone,
			VPCRef:       vpc,
			Region:       vpc.RegionName(),
		},
		InternalNode: vpcmodel.InternalNode{
			AddressStr: address,
		},
		vsi:            vsi,
		securityGroups: securityGroups,
	}

	if err := intfNode.SetIPBlockFromAddress(); err != nil {
		return nil, err
	}
	return intfNode, nil
}

func getInstancesConfig(
	rc *aws.ResourcesContainer,
	subnetIdToNetIntf map[string][]*NetworkInterface,
	res *vpcmodel.MultipleVPCConfigs,
	skipByVPC map[string]bool,
) error {
	for _, instance := range rc.InstancesList {
		vpcUID := *instance.VpcId
		if skipByVPC[vpcUID] {
			continue
		}
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		vsiNode := &Vsi{
			VPCResource: vpcmodel.VPCResource{
				ResourceUID:  *instance.InstanceId,
				Zone:         *instance.Placement.AvailabilityZone,
				ResourceType: ResourceTypeVSI,
				VPCRef:       vpc,
				Region:       vpc.RegionName(),
			},
			nodes: []vpcmodel.Node{},
		}

		if err := addZone(*instance.Placement.AvailabilityZone, vpcUID, res); err != nil {
			return err
		}
		vpcConfig := res.Config(vpcUID)
		vpcConfig.NodeSets = append(vpcConfig.NodeSets, vsiNode)
		vpcConfig.UIDToResource[vsiNode.ResourceUID] = vsiNode
		for j := range instance.NetworkInterfaces {
			netintf := instance.NetworkInterfaces[j]
			// netintf has no CRN, thus using its ID for ResourceUID
			intfNode, err := newNetworkInterface(*netintf.NetworkInterfaceId, *instance.Placement.AvailabilityZone, *netintf.PrivateIpAddress, *instance.InstanceId, vpc, netintf.Groups)
			if err != nil {
				return err
			}
			vpcConfig.Nodes = append(vpcConfig.Nodes, intfNode)
			vpcConfig.UIDToResource[intfNode.ResourceUID] = intfNode
			vsiNode.nodes = append(vsiNode.nodes, intfNode)
			subnetId := *netintf.SubnetId
			if _, ok := subnetIdToNetIntf[subnetId]; !ok {
				subnetIdToNetIntf[subnetId] = []*NetworkInterface{}
			}
			subnetIdToNetIntf[subnetId] = append(subnetIdToNetIntf[subnetId], intfNode)
		}
	}
	return nil
}

func newSubnet(uid, zone, cidr string, vpc vpcmodel.VPCResourceIntf) (*Subnet, error) {
	subnetNode := &Subnet{
		VPCResource: vpcmodel.VPCResource{
			ResourceUID:  uid,
			Zone:         zone,
			ResourceType: ResourceTypeSubnet,
			VPCRef:       vpc,
			Region:       vpc.RegionName(),
		},
		cidr: cidr,
	}

	cidrIPBlock, err := ipblock.FromCidr(subnetNode.cidr)
	if err != nil {
		return nil, err
	}
	subnetNode.ipblock = cidrIPBlock
	return subnetNode, nil
}

func getSubnetsConfig(
	res *vpcmodel.MultipleVPCConfigs,
	subnetNameToNetIntf map[string][]*NetworkInterface,
	rc *aws.ResourcesContainer,
	skipByVPC map[string]bool,
) (vpcInternalAddressRange map[string]*ipblock.IPBlock, err error) {
	vpcInternalAddressRange = map[string]*ipblock.IPBlock{}
	for vpcUID := range res.Configs() {
		vpcInternalAddressRange[vpcUID] = nil
	}
	for _, subnet := range rc.SubnetsList {
		if skipByVPC[*subnet.VpcId] {
			continue
		}
		subnetNodes := []vpcmodel.Node{}
		vpcUID := *subnet.VpcId
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return nil, err
		}

		subnetNode, err := newSubnet(*subnet.SubnetId, *subnet.AvailabilityZone, *subnet.CidrBlock, vpc)
		if err != nil {
			return nil, err
		}
		if vpcInternalAddressRange[vpcUID] == nil {
			vpcInternalAddressRange[vpcUID] = subnetNode.ipblock
		} else {
			vpcInternalAddressRange[vpcUID] = vpcInternalAddressRange[vpcUID].Union(subnetNode.ipblock)
		}
		res.Config(vpcUID).Subnets = append(res.Config(vpcUID).Subnets, subnetNode)
		if err := addZone(*subnet.AvailabilityZone, vpcUID, res); err != nil {
			return nil, err
		}
		res.Config(vpcUID).UIDToResource[subnetNode.ResourceUID] = subnetNode

		// add pointers from networkInterface to its subnet, given the current subnet created
		if subnetInterfaces, ok := subnetNameToNetIntf[*subnet.SubnetId]; ok {
			for _, netIntf := range subnetInterfaces {
				netIntf.SubnetResource = subnetNode
				subnetNodes = append(subnetNodes, netIntf)
			}
			subnetNode.nodes = subnetNodes
		}
		// add subnet to its vpc's list of subnets
		vpc.subnetsList = append(vpc.subnetsList, subnetNode)
	}
	return vpcInternalAddressRange, nil
}

func parseSGTargets(sgResources map[string]map[string]*SecurityGroup, configs *vpcmodel.MultipleVPCConfigs) {
	for vpcUID, sgs := range sgResources {
		config := configs.Config(vpcUID)
		for _, node := range config.Nodes {
			if node.Kind() == ResourceTypeNetworkInterface {
				if intfNodeObj, ok := node.(*NetworkInterface); ok {
					securityGroupIds := intfNodeObj.SecurityGroups()
					for _, securityGroupId := range securityGroupIds {
						sgs[*securityGroupId.GroupId].members[intfNodeObj.Address()] = intfNodeObj
					}
				}
			}
		}
	}
}

func getSGconfig(rc *aws.ResourcesContainer,
	res *vpcmodel.MultipleVPCConfigs,
	skipByVPC map[string]bool,
) error {
	sgMap := map[string]map[string]*SecurityGroup{} // map from vpc uid to map from sg name to its sg object
	sgLists := map[string][]*SecurityGroup{}
	for i := range rc.SecurityGroupsList {
		sg := rc.SecurityGroupsList[i]
		if skipByVPC[*sg.VpcId] {
			continue
		}
		vpcUID := *sg.VpcId
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}

		sgResource := &SecurityGroup{
			VPCResource: vpcmodel.VPCResource{
				ResourceUID:  *sg.GroupId,
				ResourceType: ResourceTypeSG,
				VPCRef:       vpc,
				Region:       vpc.RegionName(),
			},
			analyzer: NewSGAnalyzer(sg), members: map[string]vpcmodel.Node{},
		}
		if _, ok := sgMap[vpcUID]; !ok {
			sgMap[vpcUID] = map[string]*SecurityGroup{}
		}
		sgMap[vpcUID][*sg.GroupId] = sgResource
		sgLists[vpcUID] = append(sgLists[vpcUID], sgResource)
	}
	parseSGTargets(sgMap, res)
	for vpcUID, sgListInstance := range sgLists {
		vpc, err := getVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		sgLayer := &SecurityGroupLayer{
			VPCResource: vpcmodel.VPCResource{
				ResourceType: vpcmodel.SecurityGroupLayer,
				VPCRef:       vpc,
				Region:       vpc.RegionName(),
			},
			sgList: sgListInstance}
		res.Config(vpcUID).FilterResources = append(res.Config(vpcUID).FilterResources, sgLayer)
	}

	for _, vpcSgMap := range sgMap {
		for _, sg := range vpcSgMap {
			// the name of SG is unique across all SG of the VPC
			err := sg.analyzer.prepareAnalyzer(vpcSgMap, sg)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

/********** Functions used in Debug mode ***************/

func printVPCConfigs(c *vpcmodel.MultipleVPCConfigs) {
	if !logging.DebugVerbosity() {
		return
	}
	fmt.Println("VPCs to analyze:")
	for vpcUID, config := range c.Configs() {
		logging.Debugf("VPC UID: %s, Name: %s\n", vpcUID, config.VPC.Name())
	}
	printLineSection()
	for vpcUID, config := range c.Configs() {
		logging.Debugf("config for vpc %s (vpc name: %s)\n", vpcUID, config.VPC.Name())
		printConfig(config)
	}
	printLineSection()
}

func printLineSection() {
	fmt.Println("-----------------------------------------")
}

func printConfig(c *vpcmodel.VPCConfig) {
	separator := " "
	fmt.Println("Nodes:")
	for _, n := range c.Nodes {
		if n.IsExternal() {
			continue
		}
		fmt.Println(strings.Join([]string{n.Kind(), n.CidrOrAddress(), n.Name(), n.UID()}, separator))
	}
	fmt.Println("Subnets:")
	for _, n := range c.Subnets {
		fmt.Println(strings.Join([]string{n.Kind(), n.CIDR(), n.Name(), n.UID()}, separator))
	}
	fmt.Println("NodeSets:")
	for _, n := range c.NodeSets {
		fmt.Println(strings.Join([]string{n.Kind(), n.AddressRange().ToIPRanges(), n.Name(), n.UID()}, separator))
	}
	fmt.Println("FilterResources:")
	for _, f := range c.FilterResources {
		switch filters := f.(type) {
		case *SecurityGroupLayer:
			for _, sg := range filters.sgList {
				if len(sg.members) == 0 {
					continue
				}
				fmt.Println(strings.Join([]string{sg.ResourceType, sg.ResourceName, sg.UID()}, separator))
				printSGRules(sg)
			}
		}
	}
}

func printSGRules(sg *SecurityGroup) {
	numRules := len(sg.analyzer.egressRules) + len(sg.analyzer.ingressRules)

	fmt.Printf("num rules: %d\n", numRules)
	for i := 0; i < numRules; i++ {
		strRule, _, _, err := sg.analyzer.getSGRule(i)
		printRule(strRule, i, err)
	}
}

func printRule(ruleStr string, index int, err error) {
	if err == nil {
		fmt.Println(ruleStr)
	} else {
		fmt.Printf("err for rule %d: %s\n", index, err.Error())
	}
}
