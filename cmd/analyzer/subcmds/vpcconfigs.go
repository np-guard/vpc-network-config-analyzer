/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/np-guard/cloud-resource-collector/pkg/common"
	"github.com/np-guard/cloud-resource-collector/pkg/factory"
	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/ibmvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const notSupportedYet = "provider %s is not supported yet"

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

// Helper function for unmarshalling
func jsonToMap(jsonStr []byte) (map[string]json.RawMessage, error) {
	var result map[string]json.RawMessage
	err := json.Unmarshal(jsonStr, &result)
	return result, err
}

// parseProviderFromFile returns the provider (ibm or aws) from the input JSON file
func parseProviderFromFile(fileName string) (common.Provider, error) {
	inputConfigContent, err := os.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	asMap, err := jsonToMap(inputConfigContent)
	if err != nil {
		return "", err
	}
	provider := common.IBM
	val, ok := asMap["provider"]
	if ok {
		if err := json.Unmarshal(val, &provider); err != nil {
			return "", err
		}
	}
	return provider, nil
}

func vpcConfigsFromFiles(fileNames []string, inArgs *inArgs) (*vpcmodel.MultipleVPCConfigs, error) {
	var mergedRC *datamodel.ResourcesContainerModel
	for _, file := range fileNames {
		provider, err := parseProviderFromFile(file)
		if err != nil {
			return nil, err
		}
		if provider == common.IBM {
			rc, err1 := ibmvpc.ParseResourcesFromFile(file)
			if err1 != nil {
				return nil, fmt.Errorf("error parsing input vpc resources file: %w", err1)
			}
			mergedRC, err1 = mergeResourcesContainers(mergedRC, rc)
			if err1 != nil {
				return nil, err1
			}
		} else {
			return nil, fmt.Errorf(notSupportedYet, provider)
		}
	}
	vpcConfigs, err2 := ibmvpc.VPCConfigsFromResources(mergedRC, inArgs.vpc, inArgs.resourceGroup, inArgs.regionList)
	if err2 != nil {
		return nil, fmt.Errorf("error generating cloud config from input vpc resources file: %w", err2)
	}
	return vpcConfigs, nil
}

func vpcConfigsFromAccount(inArgs *inArgs) (*vpcmodel.MultipleVPCConfigs, error) {
	rc := factory.GetResourceContainer(inArgs.provider, inArgs.regionList, inArgs.resourceGroup)
	// Collect resources from the provider API and generate output
	err := rc.CollectResourcesFromAPI()
	if err != nil {
		return nil, err
	}

	var vpcConfigs *vpcmodel.MultipleVPCConfigs
	// todo: when analysis for other providers is available, select provider according to flag
	if inArgs.provider == common.IBM {
		ibmResources, ok := rc.GetResources().(*datamodel.ResourcesContainerModel)
		if !ok {
			return nil, fmt.Errorf("error casting resources to *datamodel.ResourcesContainerModel type")
		}
		vpcConfigs, err = ibmvpc.VPCConfigsFromResources(ibmResources, inArgs.vpc, inArgs.resourceGroup, inArgs.regionList)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf(notSupportedYet, inArgs.provider.String())
	}

	// save collected resources in dump file
	if inArgs.dumpResources != "" {
		jsonString, err := rc.ToJSONString()
		if err != nil {
			return nil, err
		}
		log.Printf("Dumping collected resources to file: %s", inArgs.dumpResources)

		file, err := os.Create(inArgs.dumpResources)
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

func buildConfigs(inArgs *inArgs) (vpcConfigs *vpcmodel.MultipleVPCConfigs, err error) {
	if inArgs.provider != "" {
		vpcConfigs, err = vpcConfigsFromAccount(inArgs)
		if err != nil {
			return
		}
	} else {
		vpcConfigs, err = vpcConfigsFromFiles(inArgs.inputConfigFileList, inArgs)
		if err != nil {
			return
		}
	}

	if inArgs.inputSecondConfigFile != "" {
		vpcConfigsToCompare, err := vpcConfigsFromFiles([]string{inArgs.inputSecondConfigFile}, inArgs)
		if err != nil {
			return nil, err
		}
		// we are in diff mode, checking we have only one config per file:
		if len(vpcConfigs.Configs()) != 1 || len(vpcConfigsToCompare.Configs()) != 1 {
			return nil, fmt.Errorf("diff command only supports a single configuration " +
				"for both -vpc-config and -vpc-config-second")
		}
		vpcConfigs.SetConfigsToCompare(vpcConfigsToCompare.Configs())
	}

	return vpcConfigs, nil
}
