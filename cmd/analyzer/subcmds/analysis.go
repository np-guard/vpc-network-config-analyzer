/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"fmt"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func analysisVPCConfigs(inArgs *inArgs, analysisType vpcmodel.OutputUseCase) error {
	vpcConfigs, err := buildConfigs(inArgs)
	if err != nil {
		return err
	}

	outFormat := inArgs.outputFormat.ToModelFormat()
	lbAbstraction := outFormat != vpcmodel.Debug
	og, err := vpcmodel.NewOutputGenerator(vpcConfigs,
		inArgs.grouping,
		analysisType,
		false,
		inArgs.explanationArgs, outFormat, lbAbstraction)
	if err != nil {
		return err
	}

	analysisOut, err := og.Generate(outFormat, inArgs.outputFile)
	if err != nil {
		return fmt.Errorf("output generation error: %w", err)
	}

	fmt.Println(analysisOut)
	return nil
}
