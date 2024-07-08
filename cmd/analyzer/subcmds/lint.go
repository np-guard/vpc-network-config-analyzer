/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"github.com/spf13/cobra"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/linter"
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

	multiConfigs, err := buildConfigs(inArgs)
	if err != nil {
		return err
	}
	linter.LinterExecute(multiConfigs.Configs())
	return nil
}
