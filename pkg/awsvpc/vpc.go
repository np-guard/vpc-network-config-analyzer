/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

func nameWithBracketsInfo(name, inBrackets string) string {
	return fmt.Sprintf("%s[%s]", name, inBrackets)
}

// NetworkInterface implements vpcmodel.Node interface
type NetworkInterface struct {
	vpcmodel.VPCResource
	vpcmodel.InternalNode
	vsi            string
	securityGroups []types.GroupIdentifier
}

func (ni *NetworkInterface) VsiName() string {
	return ni.vsi
}

func (ni *NetworkInterface) SecurityGroups() []types.GroupIdentifier {
	return ni.securityGroups
}

func (ni *NetworkInterface) Name() string {
	return nameWithBracketsInfo(ni.vsi, ni.Address())
}

func (ni *NetworkInterface) ExtendedName(c *vpcmodel.VPCConfig) string {
	return ni.ExtendedPrefix(c) + ni.Name()
}
