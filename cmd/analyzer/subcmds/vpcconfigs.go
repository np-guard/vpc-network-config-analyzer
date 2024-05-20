/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"fmt"
	"log"
	"os"

	"github.com/np-guard/cloud-resource-collector/pkg/factory"
	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/ibmvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const (
	inGenerationErr = "error generating cloud config from input vpc resources file:"
	errorFormat     = "%s %w"
)

func mergeResourcesContainers(rc1, rc2 *datamodel.ResourcesContainerModel) (*datamodel.ResourcesContainerModel, error) {
	if rc2 == nil && rc1 != nil {
		return rc1, nil
	}
	if rc2 != nil && rc1 == nil {
		return rc2, nil
	}
	if rc2 == nil && rc1 == nil {
		return nil, fmt.Errorf("error merging input vpc resources files")
	}
	rc1.VpcList = append(rc1.VpcList, rc2.VpcList...)
	rc1.SubnetList = append(rc1.SubnetList, rc2.SubnetList...)
	rc1.PublicGWList = append(rc1.PublicGWList, rc2.PublicGWList...)
	rc1.FloatingIPList = append(rc1.FloatingIPList, rc2.FloatingIPList...)
	rc1.NetworkACLList = append(rc1.NetworkACLList, rc2.NetworkACLList...)
	rc1.SecurityGroupList = append(rc1.SecurityGroupList, rc2.SecurityGroupList...)
	rc1.EndpointGWList = append(rc1.EndpointGWList, rc2.EndpointGWList...)
	rc1.InstanceList = append(rc1.InstanceList, rc2.InstanceList...)
	rc1.RoutingTableList = append(rc1.RoutingTableList, rc2.RoutingTableList...)
	rc1.LBList = append(rc1.LBList, rc2.LBList...)
	rc1.TransitConnectionList = append(rc1.TransitConnectionList, rc2.TransitConnectionList...)
	rc1.TransitGatewayList = append(rc1.TransitGatewayList, rc2.TransitGatewayList...)
	rc1.IKSClusters = append(rc1.IKSClusters, rc2.IKSClusters...)

	return rc1, nil
}

func vpcConfigsFromFiles(fileNames []string, inArgs *InArgs) (*vpcmodel.MultipleVPCConfigs, error) {
	var mergedRC *datamodel.ResourcesContainerModel
	for _, file := range fileNames {
		rc, err1 := ibmvpc.ParseResourcesFromFile(file)
		if err1 != nil {
			return nil, fmt.Errorf("error parsing input vpc resources file: %w", err1)
		}
		mergedRC, err1 = mergeResourcesContainers(mergedRC, rc)
		if err1 != nil {
			return nil, err1
		}
	}
	vpcConfigs, err2 := ibmvpc.VPCConfigsFromResources(mergedRC, inArgs.VPC, inArgs.ResourceGroup, inArgs.RegionList, inArgs.Debug)
	if err2 != nil {
		return nil, fmt.Errorf(errorFormat, inGenerationErr, err2)
	}
	return vpcConfigs, nil
}

func vpcConfigsFromAccount(inArgs *InArgs) (*vpcmodel.MultipleVPCConfigs, error) {
	rc := factory.GetResourceContainer(string(inArgs.Provider), inArgs.RegionList, inArgs.ResourceGroup)
	// Collect resources from the provider API and generate output
	err := rc.CollectResourcesFromAPI()
	if err != nil {
		return nil, err
	}

	// todo: when analysis for other providers is available, select provider according to flag
	resources, ok := rc.GetResources().(*datamodel.ResourcesContainerModel)
	if !ok {
		return nil, fmt.Errorf("error casting resources to *datamodel.ResourcesContainerModel type")
	}
	vpcConfigs, err := ibmvpc.VPCConfigsFromResources(resources, inArgs.VPC, inArgs.ResourceGroup, inArgs.RegionList, inArgs.Debug)
	if err != nil {
		return nil, err
	}
	// save collected resources in dump file
	if inArgs.DumpResources != "" {
		jsonString, err := resources.ToJSONString()
		if err != nil {
			return nil, err
		}
		log.Printf("Dumping collected resources to file: %s", inArgs.DumpResources)

		file, err := os.Create(inArgs.DumpResources)
		if err != nil {
			return nil, err
		}

		_, err = file.WriteString(jsonString)
		if err != nil {
			return nil, err
		}
	}
	return vpcConfigs, nil
}

func buildConfigs(inArgs *InArgs) error {
	var err error
	if inArgs.Provider != "" {
		inArgs.VpcConfigs, err = vpcConfigsFromAccount(inArgs)
		if err != nil {
			return err
		}
	} else {
		inArgs.VpcConfigs, err = vpcConfigsFromFiles(inArgs.InputConfigFileList, inArgs)
		if err != nil {
			return err
		}
	}

	if inArgs.InputSecondConfigFile != "" {
		vpcConfigsToCompare, err := vpcConfigsFromFiles([]string{inArgs.InputSecondConfigFile}, inArgs)
		if err != nil {
			return err
		}
		// we are in diff mode, checking we have only one config per file:
		if len(inArgs.VpcConfigs.Configs()) != 1 || len(vpcConfigsToCompare.Configs()) != 1 {
			return fmt.Errorf("for diff mode %v a single configuration should be provided "+
				"for both -vpc-config and -vpc-config-second", inArgs.AnalysisType)
		}
		inArgs.VpcConfigs.SetConfigsToCompare(vpcConfigsToCompare.Configs())
	}

	return nil
}
