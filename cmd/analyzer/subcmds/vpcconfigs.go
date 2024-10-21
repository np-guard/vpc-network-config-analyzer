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
	"github.com/np-guard/vpc-network-config-analyzer/pkg/awsvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/ibmvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const notSupportedYet = "provider %s is not supported yet"

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
	// len(fileNames) can not be zero
	provider, err := parseProviderFromFile(fileNames[0])
	if err != nil {
		return nil, err
	}
	var rc commonvpc.ResourcesContainer
	switch provider {
	case common.IBM:
		vpcmodel.InitNetworkAddressLists(ibmvpc.GetPublicInternetAddressList(), ibmvpc.GetServiceNetworkAddressList())
		rc = &ibmvpc.IBMresourcesContainer{}
	case common.AWS:
		vpcmodel.InitNetworkAddressLists(awsvpc.GetPublicInternetAddressList(), nil)
		rc = &awsvpc.AWSresourcesContainer{}
	default:
		return nil, fmt.Errorf(notSupportedYet, provider)
	}
	return rc.VpcConfigsFromFiles(fileNames, inArgs.resourceGroup, inArgs.vpcList, inArgs.regionList)
}

func vpcConfigsFromAccount(inArgs *inArgs) (*vpcmodel.MultipleVPCConfigs, error) {
	rc := factory.GetResourceContainer(inArgs.provider, inArgs.regionList, inArgs.resourceGroup)
	// Collect resources from the provider API and generate output
	err := rc.CollectResourcesFromAPI()
	if err != nil {
		return nil, err
	}

	var commonRC commonvpc.ResourcesContainer
	switch inArgs.provider {
	case common.IBM:
		commonRC, err = ibmvpc.NewIBMresourcesContainer(rc)
	case common.AWS:
		commonRC, err = awsvpc.NewAWSresourcesContainer(rc)
	default:
		return nil, fmt.Errorf(notSupportedYet, inArgs.provider.String())
	}

	if err != nil {
		return nil, err
	}

	vpcConfigs, err := commonRC.VPCConfigsFromResources(inArgs.resourceGroup, inArgs.vpcList, inArgs.regionList)
	if err != nil {
		return nil, err
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
				"for both --config and --config-second")
		}
		vpcConfigs.SetConfigsToCompare(vpcConfigsToCompare.Configs())
	}

	return vpcConfigs, nil
}
