/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func TestGroupingUnification(t *testing.T) {
	vpcConfigMultiVpc := getConfig(t, "iks_workers_large")
	require.NotNil(t, vpcConfigMultiVpc, "vpcConfigMultiVpc equals nil")

	og, err := vpcmodel.NewOutputGenerator(vpcConfigMultiVpc, true,
		vpcmodel.AllEndpoints, false, nil, vpcmodel.DRAWIO, true, false)
	if err != nil {
		fmt.Println(err.Error())
	}
	require.Nil(t, err, "NewOutputGenerator should not have an error")

	nonUnifiedPointers := og.UnificationDebugPrint()
	fmt.Println("nonUnifiedPointers are:", nonUnifiedPointers)
	require.Equal(t, "", nonUnifiedPointers, "each group should have a single reference")
}
