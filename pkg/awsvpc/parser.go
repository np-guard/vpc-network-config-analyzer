/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/np-guard/cloud-resource-collector/pkg/aws"
	"github.com/np-guard/cloud-resource-collector/pkg/common"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/logging"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const resourceNameKey = "Name"

// AWSresourcesContainer implements commonvpc.ResourceContainer
type AWSresourcesContainer struct {
	aws.ResourcesContainer
}

// NewAWSresourcesContainer is used to return empty NewAWSresourcesContainer and also initialize
// vpcmodel.NetworkAddressLists with aws Public internet and service network
// if you do not use this function, you need to initialize vpcmodel.NetworkAddressLists
func NewAWSresourcesContainer() *AWSresourcesContainer {
	vpcmodel.InitNetworkAddressLists(vpcmodel.GetDefaultPublicInternetAddressList(), []string{})
	return &AWSresourcesContainer{}
}

func CopyAWSresourcesContainer(rc common.ResourcesContainerInf) (*AWSresourcesContainer, error) {
	awsResources, ok := rc.GetResources().(*aws.ResourcesContainer)
	if !ok {
		return nil, fmt.Errorf("error casting resources to *aws.ResourcesContainerModel type")
	}
	return &AWSresourcesContainer{ResourcesContainer: *awsResources}, nil
}

// parseResourcesFromFile returns aws.ResourcesContainer object, containing the configured resources structs
// from the input JSON file
func (rc *AWSresourcesContainer) ParseResourcesFromFile(fileName string) error {
	inputConfigContent, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}
	err = json.Unmarshal(inputConfigContent, &rc)
	if err != nil {
		return err
	}
	return nil
}

func mergeResourcesContainers(rc1, rc2 *AWSresourcesContainer) (*AWSresourcesContainer, error) {
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

// VpcConfigsFromFiles gets file names and returns vpc configs from it
// vpcID, resourceGroup and regions are used to filter the vpc configs.
// resourceGroup nad regions are not supported yet for aws
func (rc *AWSresourcesContainer) VpcConfigsFromFiles(fileNames []string, resourceGroup string, vpcIDs, regions []string) (
	*vpcmodel.MultipleVPCConfigs, error) {
	for _, file := range fileNames {
		mergedRC := NewAWSresourcesContainer()
		err1 := mergedRC.ParseResourcesFromFile(file)
		if err1 != nil {
			return nil, fmt.Errorf("error parsing input vpc resources file: %w", err1)
		}
		rc, err1 = mergeResourcesContainers(mergedRC, rc)
		if err1 != nil {
			return nil, err1
		}
	}
	vpcConfigs, err2 := rc.VPCConfigsFromResources(resourceGroup, vpcIDs, regions)
	if err2 != nil {
		return nil, fmt.Errorf("error generating cloud config from input vpc resources file: %w", err2)
	}
	return vpcConfigs, nil
}

// filterByVpc returns a map to filtered resources, if certain VPC to analyze is specified by the user,
// skip resources configured outside that VPC
func (rc *AWSresourcesContainer) filterByVpc(vpcIDs []string) map[string]bool {
	shouldSkipVpcIds := make(map[string]bool)
	for _, vpc := range rc.VpcsList {
		if len(vpcIDs) > 0 && !slices.Contains(vpcIDs, *vpc.VpcId) {
			shouldSkipVpcIds[*vpc.VpcId] = true
		}
	}
	return shouldSkipVpcIds
}

// VPCConfigsFromResources returns a map from VPC UID (string) to its corresponding VPCConfig object,
// containing the parsed resources in the relevant model objects
func (rc *AWSresourcesContainer) VPCConfigsFromResources(resourceGroup string, vpcIDs, regions []string) (
	*vpcmodel.MultipleVPCConfigs, error) {
	res := vpcmodel.NewMultipleVPCConfigs(common.AWS)       // map from VPC UID to its config
	regionToStructMap := make(map[string]*commonvpc.Region) // map for caching Region objects
	var err error

	// map to filter resources, if certain VPC to analyze is specified,
	// skip resources configured outside that VPC
	shouldSkipVpcIds := rc.filterByVpc(vpcIDs)

	err = rc.getVPCconfig(res, shouldSkipVpcIds, regionToStructMap)
	if err != nil {
		return nil, err
	}

	var vpcInternalAddressRange map[string]*ipblock.IPBlock // map from vpc name to its internal address range

	subnetIDToNetIntf := map[string][]*commonvpc.NetworkInterface{}
	netIntfToSGs := map[string][]types.GroupIdentifier{}
	err = rc.getInstancesConfig(subnetIDToNetIntf, netIntfToSGs, res, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}
	vpcInternalAddressRange, err = rc.getSubnetsConfig(res, subnetIDToNetIntf, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}
	// assign to each vpc object its internal address range, as inferred from its subnets
	err = commonvpc.UpdateVPCSAddressRanges(vpcInternalAddressRange, res)
	if err != nil {
		return nil, err
	}

	err = rc.getSGconfig(res, shouldSkipVpcIds, netIntfToSGs)
	if err != nil {
		return nil, err
	}

	err = rc.getNACLconfig(res, shouldSkipVpcIds)
	if err != nil {
		return nil, err
	}

	err = commonvpc.FilterVPCSAndAddExternalNodes(vpcInternalAddressRange, res)
	if err != nil {
		return nil, err
	}
	rc.getIgwConfig(res, shouldSkipVpcIds)
	printVPCConfigs(res)

	return res, nil
}

// get name from tags, if not fount return alternateName
func getResourceName(tags []types.Tag, alternateName *string) *string {
	for _, tag := range tags {
		if *tag.Key == resourceNameKey {
			return tag.Value
		}
	}
	return alternateName
}

func (rc *AWSresourcesContainer) getVPCconfig(
	res *vpcmodel.MultipleVPCConfigs,
	skipByVPC map[string]bool,
	regionToStructMap map[string]*commonvpc.Region) error {
	for _, vpc := range rc.VpcsList {
		if skipByVPC[*vpc.VpcId] {
			continue // skip vpc not specified to analyze
		}
		vpcName := getResourceName(vpc.Tags, vpc.VpcId)
		vpcNodeSet, err := commonvpc.NewVPC(*vpcName, *vpc.VpcId, vpc.Region, nil, regionToStructMap)
		if err != nil {
			return err
		}

		newVPCConfig := commonvpc.NewEmptyVPCConfig()
		newVPCConfig.UIDToResource[vpcNodeSet.ResourceUID] = vpcNodeSet
		newVPCConfig.VPC = vpcNodeSet
		res.SetConfig(vpcNodeSet.ResourceUID, newVPCConfig)
	}
	if len(res.Configs()) == 0 {
		return errors.New("could not find any VPC to analyze")
	}
	return nil
}

func (rc *AWSresourcesContainer) getInstancesConfig(
	subnetIDToNetIntf map[string][]*commonvpc.NetworkInterface,
	netIntfToSGs map[string][]types.GroupIdentifier,
	res *vpcmodel.MultipleVPCConfigs,
	skipByVPC map[string]bool) error {
	for _, instance := range rc.InstancesList {
		if instance.State.Name != types.InstanceStateNameRunning {
			continue
		}
		vpcUID := *instance.VpcId
		if skipByVPC[vpcUID] {
			continue
		}
		vpc, err := commonvpc.GetVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		instanceName := getResourceName(instance.Tags, instance.InstanceId)
		vsiNode, err := commonvpc.NewVSI(*instanceName, *instance.InstanceId, *instance.Placement.AvailabilityZone, vpc, res)
		if err != nil {
			return err
		}
		vpcConfig := res.Config(vpcUID)
		vpcConfig.NodeSets = append(vpcConfig.NodeSets, vsiNode)
		vpcConfig.UIDToResource[vsiNode.ResourceUID] = vsiNode
		for j := range instance.NetworkInterfaces {
			netintf := instance.NetworkInterfaces[j]
			intfNode, err := commonvpc.NewNetworkInterface(*netintf.NetworkInterfaceId, *netintf.NetworkInterfaceId,
				*instance.Placement.AvailabilityZone, *netintf.PrivateIpAddress, *instanceName, len(instance.NetworkInterfaces), false, vpc)
			if err != nil {
				return err
			}
			netIntfToSGs[*netintf.NetworkInterfaceId] = netintf.Groups
			vpcConfig.Nodes = append(vpcConfig.Nodes, intfNode)
			vpcConfig.UIDToResource[intfNode.ResourceUID] = intfNode
			vsiNode.VPCnodes = append(vsiNode.VPCnodes, intfNode)
			subnetID := *netintf.SubnetId
			if _, ok := subnetIDToNetIntf[subnetID]; !ok {
				subnetIDToNetIntf[subnetID] = []*commonvpc.NetworkInterface{}
			}
			subnetIDToNetIntf[subnetID] = append(subnetIDToNetIntf[subnetID], intfNode)
		}
	}
	return nil
}

func (rc *AWSresourcesContainer) getSubnetsConfig(
	res *vpcmodel.MultipleVPCConfigs,
	subnetNameToNetIntf map[string][]*commonvpc.NetworkInterface,
	skipByVPC map[string]bool,
) (vpcInternalAddressRange map[string]*ipblock.IPBlock, err error) {
	vpcInternalAddressRange = map[string]*ipblock.IPBlock{}
	for vpcUID := range res.Configs() {
		vpcInternalAddressRange[vpcUID] = nil
	}
	for _, subnetObj := range rc.SubnetsList {
		if skipByVPC[*subnetObj.VpcId] {
			continue
		}
		subnetName := getResourceName(subnetObj.Tags, subnetObj.SubnetId)
		subnet, err := commonvpc.UpdateConfigWithSubnet(*subnetName,
			*subnetObj.SubnetId, *subnetObj.AvailabilityZone, *subnetObj.CidrBlock,
			*subnetObj.VpcId, res, vpcInternalAddressRange, subnetNameToNetIntf)
		if err != nil {
			return nil, err
		}
		subnet.SetIsPrivate(!*subnetObj.MapPublicIpOnLaunch)
	}
	return vpcInternalAddressRange, nil
}

func parseSGTargets(sgResources map[string]map[string]*commonvpc.SecurityGroup,
	netIntfToSGs map[string][]types.GroupIdentifier,
	configs *vpcmodel.MultipleVPCConfigs) {
	for vpcUID, sgs := range sgResources {
		config := configs.Config(vpcUID)
		for _, node := range config.Nodes {
			if node.Kind() == commonvpc.ResourceTypeNetworkInterface {
				if intfNodeObj, ok := node.(*commonvpc.NetworkInterface); ok {
					securityGroupIds := netIntfToSGs[intfNodeObj.ResourceUID]
					for _, securityGroupID := range securityGroupIds {
						sgs[*securityGroupID.GroupId].Members[intfNodeObj.Address()] = intfNodeObj
					}
				}
			}
		}
	}
}

func (rc *AWSresourcesContainer) getSGconfig(
	res *vpcmodel.MultipleVPCConfigs,
	skipByVPC map[string]bool,
	netIntfToSGs map[string][]types.GroupIdentifier) error {
	sgMap := map[string]map[string]*commonvpc.SecurityGroup{} // map from vpc uid to map from sg id to its sg object
	sgLists := map[string][]*commonvpc.SecurityGroup{}
	for i := range rc.SecurityGroupsList {
		sg := rc.SecurityGroupsList[i]
		if skipByVPC[*sg.VpcId] {
			continue
		}
		vpcUID := *sg.VpcId
		vpc, err := commonvpc.GetVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		sgName := getResourceName(sg.Tags, sg.GroupId)
		commonvpc.NewSGResource(*sgName, *sg.GroupId, *sg.GroupId, vpc, NewAWSSGAnalyzer(sg), sgMap, sgLists)
	}
	parseSGTargets(sgMap, netIntfToSGs, res)
	err := commonvpc.UpdateConfigWithSG(res, sgLists)
	if err != nil {
		return err
	}

	err = commonvpc.PrepareAnalyzers(sgMap)
	if err != nil {
		return err
	}

	return nil
}

func (rc *AWSresourcesContainer) getNACLconfig(
	res *vpcmodel.MultipleVPCConfigs,
	skipByVPC map[string]bool,
) error {
	naclLists := map[string][]*commonvpc.NACL{} // map from vpc uid to its nacls
	for _, nacl := range rc.NetworkACLsList {
		if skipByVPC[*nacl.VpcId] {
			continue
		}
		naclAnalyzer, err := commonvpc.NewNACLAnalyzer(NewAWSNACLAnalyzer(nacl))
		if err != nil {
			return err
		}
		vpcUID := *nacl.VpcId
		vpc, err := commonvpc.GetVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		naclName := getResourceName(nacl.Tags, nacl.NetworkAclId)
		naclResource := &commonvpc.NACL{
			VPCResource: vpcmodel.VPCResource{
				ResourceName: *naclName,
				ResourceUID:  *nacl.NetworkAclId,
				ResourceType: commonvpc.ResourceTypeNACL,
				VPCRef:       vpc,
				Region:       vpc.RegionName(),
			},
			Analyzer: naclAnalyzer, Subnets: map[string]*commonvpc.Subnet{}}
		naclLists[vpcUID] = append(naclLists[vpcUID], naclResource)
		for i := range nacl.Associations {
			subnetRef := &nacl.Associations[i]
			subnetCRN := *subnetRef.SubnetId
			if subnetResource, ok := res.Config(vpcUID).UIDToResource[subnetCRN]; ok {
				if subnet, ok := subnetResource.(*commonvpc.Subnet); ok {
					naclResource.Subnets[subnet.Cidr] = subnet
				} else {
					return fmt.Errorf("getNACLconfig: could not find subnetRef by CRN")
				}
			}
		}
	}

	for vpcUID, vpcConfig := range res.Configs() {
		vpc, err := commonvpc.GetVPCObjectByUID(res, vpcUID)
		if err != nil {
			return err
		}
		naclLayer := &commonvpc.NaclLayer{
			VPCResource: vpcmodel.VPCResource{
				ResourceType: vpcmodel.NaclLayer,
				VPCRef:       vpc,
				Region:       vpc.RegionName(),
			},
			NaclList: naclLists[vpcUID]}
		vpcConfig.FilterResources = append(vpcConfig.FilterResources, naclLayer)
	}
	return nil
}

func (rc *AWSresourcesContainer) getIgwConfig(
	res *vpcmodel.MultipleVPCConfigs,
	skipByVPC map[string]bool) {
	for _, igw := range rc.InternetGWList {
		igwID := igw.InternetGatewayId
		igwName := getResourceName(igw.Tags, igwID)
		if len(igw.Attachments) != 1 {
			logging.Warnf("skipping internet gateway %s - it has %d vpcs attached\n", *igwName, len(igw.Attachments))
			continue
		}
		vpcUID := *igw.Attachments[0].VpcId
		if skipByVPC[vpcUID] {
			continue
		}
		vpc := res.GetVPC(vpcUID).(*commonvpc.VPC)
		subnets := vpc.Subnets()

		if len(subnets) == 0 {
			logging.Warnf("skipping internet gateway %s - it does not have any attached subnet\n", *igwName)
			continue
		}
		routerIgw := newIGW(*igwName, *igwID, subnets, vpc)
		res.Config(vpcUID).RoutingResources = append(res.Config(vpcUID).RoutingResources, routerIgw)
		res.Config(vpcUID).UIDToResource[routerIgw.ResourceUID] = routerIgw
	}
}

func newIGW(igwName, igwCRN string, subnets []*commonvpc.Subnet, vpc vpcmodel.VPC) *InternetGateway {
	srcNodes := commonvpc.GetSubnetsNodes(subnets)
	return &InternetGateway{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: igwName,
			ResourceUID:  igwCRN,
			ResourceType: commonvpc.ResourceTypeInternetGateway,
			Region:       vpc.RegionName(),
		},
		src:        srcNodes,
		srcSubnets: subnets,
		vpc:        vpc,
	}
}

/********** Functions used in Debug mode ***************/

func printVPCConfigs(c *vpcmodel.MultipleVPCConfigs) {
	if !logging.DebugVerbosity() {
		return
	}
	logging.Debug("VPCs to analyze:")
	for vpcUID, config := range c.Configs() {
		logging.Debugf("VPC UID: %s, Name: %s\n", vpcUID, config.VPC.Name())
	}
	commonvpc.PrintLineSection()
	for vpcUID, config := range c.Configs() {
		logging.Debugf("config for vpc %s (vpc name: %s)\n", vpcUID, config.VPC.Name())
		printConfig(config)
	}
	commonvpc.PrintLineSection()
}

func printConfig(c *vpcmodel.VPCConfig) {
	separator := " "
	logging.Debug("Nodes:")
	for _, n := range c.Nodes {
		if n.IsExternal() {
			continue
		}
		logging.Debug(strings.Join([]string{n.Kind(), n.CidrOrAddress(), n.NameForAnalyzerOut(c), n.UID()}, separator))
	}
	logging.Debug("Subnets:")
	for _, n := range c.Subnets {
		logging.Debug(strings.Join([]string{n.Kind(), n.CIDR(), n.NameForAnalyzerOut(c), n.UID()}, separator))
	}
	logging.Debug("NodeSets:")
	for _, n := range c.NodeSets {
		logging.Debug(strings.Join([]string{n.Kind(), n.AddressRange().ToIPRanges(), n.NameForAnalyzerOut(c), n.UID()}, separator))
	}
	logging.Debug("FilterResources:")
	for _, f := range c.FilterResources {
		switch filters := f.(type) {
		case *commonvpc.SecurityGroupLayer:
			for _, sg := range filters.SgList {
				if len(sg.Members) == 0 {
					continue
				}
				logging.Debug(strings.Join([]string{sg.ResourceType, sg.ResourceName, sg.UID()}, separator))
				commonvpc.PrintSGRules(sg)
			}
		case *commonvpc.NaclLayer:
			for _, nacl := range filters.NaclList {
				if len(nacl.Subnets) == 0 {
					continue
				}
				logging.Debug(strings.Join([]string{nacl.ResourceType, nacl.ResourceName, nacl.UID()}, separator))
				commonvpc.PrintNACLRules(nacl)
			}
		default:
			logging.Debug("layer not supported yet")
		}
	}
}
