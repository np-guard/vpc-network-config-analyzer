/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)
func (igw *InternetGateway) ShowOnSubnetMode() bool { return true }

func (igw *InternetGateway) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewTransitGatewayTreeNode(gen.TreeNode(igw.Region()).(*drawio.RegionTreeNode), igw.Name())
}
