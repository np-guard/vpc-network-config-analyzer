/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/linter"
	"github.com/spf13/cobra"
)

func NewLintCommand(args *inArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lint",
		Short: "linting",
		Long:  `Execute various (configurable) linting and provides findings`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return lintVPCConfigs(cmd, args)
		},
	}
	return cmd
}

func lintVPCConfigs(cmd *cobra.Command, inArgs *inArgs) error {
	cmd.SilenceUsage = true  // if we got this far, flags are syntactically correct, so no need to print usage
	cmd.SilenceErrors = true // also, error will be printed to logger in main(), so no need for cobra to also print it

	vpcConfigs, err := buildConfigs(inArgs)
	if err != nil {
		return err
	}
	// takes the first vpcConfig, for now
	for _, vpcConfig := range vpcConfigs.Configs() {
		linter.LinterExecute(vpcConfig)
		return nil
	}
	return nil
}