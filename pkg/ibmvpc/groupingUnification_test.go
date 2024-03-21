package ibmvpc

import (
	"fmt"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGroupingUnification(t *testing.T) {
	vpcConfigMultiVpc := getConfig(t, "tgw_larger_example")
	require.NotNil(t, vpcConfigMultiVpc, "vpcConfigMultiVpc equals nil")

	og, err := vpcmodel.NewOutputGenerator(vpcConfigMultiVpc, nil, true,
		vpcmodel.AllEndpoints, false, nil, vpcmodel.DRAWIO)
	if err != nil {
		fmt.Println(err.Error())
	}
	require.Nil(t, err, "NewOutputGenerator should not have an error")

	nonUnifiedPointers := og.UnificationDebugPrint()
	fmt.Println("nonUnifiedPointers is", nonUnifiedPointers)
	require.Equal(t, "", nonUnifiedPointers, "each group should have a single reference")
}
