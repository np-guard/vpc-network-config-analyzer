/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func analysisVPCConfigs(cmd *cobra.Command, inArgs *inArgs, analysisType vpcmodel.OutputUseCase) error {
	cmd.SilenceUsage = true  // if we got this far, flags are syntactically correct, so no need to print usage
	cmd.SilenceErrors = true // also, error will be printed to logger in main(), so no need for cobra to also print it

	vpcConfigs, err := buildConfigs(inArgs)
	if err != nil {
		return err
	}
	outFormat := inArgs.outputFormat.ToModelFormat()
	// todo - the lbAbstraction should be derived from a flag "debug", when we will have one
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
