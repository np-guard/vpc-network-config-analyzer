/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"github.com/np-guard/models/pkg/spec"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
)

// FormattableResource is the interface of all the resources that are converted to a drawio treeNodes
type FormattableResource interface {
	GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface
	IsExternal() bool
	ShowOnSubnetMode() bool
	Kind() string
	// used for synthesis output.
	// first out will be the name of the resource from the config,
	// overridden in nif resource (if the vsi of the nif has one nif we return name of the vsi and number of nifs)
	DetailedResourceForSynthesisOut() (name string, details int)
	SynthesisKind() spec.ResourceType
}
