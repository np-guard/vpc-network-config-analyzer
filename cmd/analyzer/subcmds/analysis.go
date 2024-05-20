/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"fmt"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func analysisVPCConfigs(inArgs *inArgs) error {
	outFormat := inArgs.outputFormat.ToModelFormat()
	og, err := vpcmodel.NewOutputGenerator(inArgs.vpcConfigs,
		inArgs.grouping,
		inArgs.analysisType,
		false,
		inArgs.explanationArgs, outFormat)
	if err != nil {
		return err
	}

	analysisOut, err := og.Generate(outFormat, inArgs.outputFile)
	if err != nil {
		return fmt.Errorf(errorFormat, "output generation error:", err)
	}

	fmt.Println(analysisOut)
	return nil
}
