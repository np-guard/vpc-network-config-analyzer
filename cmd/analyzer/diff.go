/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import "github.com/spf13/cobra"

const secondConfigFlag = "vpc-config-second"

func NewDiffCommand(args *InArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Diff connectivity postures as implied by two VPC configs",
		Long: `reports changes in connectivity (modified, added and removed connections)
		between two VPC configurations`,
		Args: func(cmd *cobra.Command, args []string) error {
			return cobra.NoArgs(cmd, args)
		},
	}

	cmd.PersistentFlags().StringVar(&args.InputSecondConfigFile, secondConfigFlag, "", "file path to the 2nd input config")
	cmd.MarkPersistentFlagRequired(secondConfigFlag)

	cmd.AddCommand(newDiffEndpointsCommand(args))
	cmd.AddCommand(newDiffSubnetsCommand(args))

	return cmd
}

func newDiffEndpointsCommand(args *InArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "endpoints",
		Short: "Diff connectivity between endpoints",
		Long:  `reports changes in endpoint connectivity between two VPC configurations`,
		Args: func(cmd *cobra.Command, args []string) error {
			return cobra.NoArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			args.AnalysisType = allEndpointsDiff
			return analyze(args)
		},
	}
	return cmd
}

func newDiffSubnetsCommand(args *InArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "subnets",
		Short: "Diff connectivity between subnets",
		Long:  `reports changes in subnet connectivity between two VPC configurations`,
		Args: func(cmd *cobra.Command, args []string) error {
			return cobra.NoArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			args.AnalysisType = allSubnetsDiff
			return analyze(args)
		},
	}
	return cmd
}
