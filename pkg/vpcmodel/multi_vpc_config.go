/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package vpcmodel

import (
	"fmt"
	"strings"

	collector_common "github.com/np-guard/cloud-resource-collector/pkg/common"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// MultipleVPCConfigs captures a set of VPCConfig objects, as a map from vpcID to the VPCConfig
// Once multivpc support is elaborating , the struct may change
// thus, please use get/set methods to access the structs; avoid direct access
type MultipleVPCConfigs struct {
	configs           map[string]*VPCConfig // a map from the vpc resource uid to the vpc config
	toCompareConfigs  map[string]*VPCConfig // a map from the vpc resource uid to the vpc config that we want to compare
	provider          collector_common.Provider
	// publicNetworkNode - the EndpointElem that represent all the cidr which are not in ant vpc:
	publicNetworkNode EndpointElem
}

func NewMultipleVPCConfigs(provider collector_common.Provider) *MultipleVPCConfigs {
	return &MultipleVPCConfigs{map[string]*VPCConfig{}, nil, provider, nil}
}

func (c *MultipleVPCConfigs) Configs() map[string]*VPCConfig {
	return c.configs
}
func (c *MultipleVPCConfigs) SetConfig(uid string, config *VPCConfig) {
	c.configs[uid] = config
}
func (c *MultipleVPCConfigs) RemoveConfig(uid string) {
	delete(c.configs, uid)
}
func (c *MultipleVPCConfigs) Config(uid string) *VPCConfig {
	return c.configs[uid]
}
func (c *MultipleVPCConfigs) aConfig() *VPCConfig {
	_, config := common.AnyMapEntry(c.configs)
	return config
}
func (c *MultipleVPCConfigs) HasConfig(uid string) bool {
	_, ok := c.configs[uid]
	return ok
}
func (c *MultipleVPCConfigs) ConfigToCompare(uid string) *VPCConfig {
	return c.toCompareConfigs[uid]
}
func (c *MultipleVPCConfigs) aConfigToCompare() *VPCConfig {
	_, config := common.AnyMapEntry(c.toCompareConfigs)
	return config
}
func (c *MultipleVPCConfigs) SetConfigsToCompare(toCompare map[string]*VPCConfig) {
	c.toCompareConfigs = toCompare
}
func (c *MultipleVPCConfigs) CloudName() string {
	return strings.ToUpper(string(c.provider)) + " Cloud"
}
func (c *MultipleVPCConfigs) Provider() collector_common.Provider {
	return c.provider
}

func (c *MultipleVPCConfigs) AddConfig(config *VPCConfig) {
	if config == nil {
		return
	}
	if _, ok := c.configs[config.VPC.UID()]; !ok {
		c.configs[config.VPC.UID()] = config
	}
}

func (c *MultipleVPCConfigs) GetInternalNodeFromAddress(address string) (InternalNodeIntf, error) {
	for _, vpc := range c.configs {
		for _, node := range vpc.Nodes {
			if node.CidrOrAddress() == address {
				return node.(InternalNodeIntf), nil
			}
		}
	}
	return nil, fmt.Errorf("could not find internal node with given address %s", address)
}

func (c *MultipleVPCConfigs) GetVPC(uid string) VPCResourceIntf {
	config, ok := c.configs[uid]
	if !ok {
		return nil
	}
	return config.VPC
}

func (c *MultipleVPCConfigs) GetInternalNodesFromAllVPCs() (res []Node) {
	for _, vpcConfig := range c.configs {
		if vpcConfig.IsMultipleVPCsConfig {
			continue
		}
		for _, n := range vpcConfig.Nodes {
			if n.IsInternal() {
				res = append(res, n)
			}
		}
	}
	return res
}

func (c *MultipleVPCConfigs) GetInternalNodePairs() (res []common.Pair[Node]) {
	allNodes := c.GetInternalNodesFromAllVPCs()
	for _, n1 := range allNodes {
		for _, n2 := range allNodes {
			if n1.UID() != n2.UID() {
				res = append(res, common.Pair[Node]{Src: n1, Dst: n2})
			}
		}
	}
	return res
}
