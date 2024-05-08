/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"github.com/spf13/cobra"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const secondConfigFlag = "vpc-config-second"

func NewDiffCommand(args *InArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Diff connectivity postures as implied by two VPC configs",
		Long: `Report changes in connectivity (modified, added and removed connections)
		between two VPC configurations`,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			return validateFormatForMode("diff", []formatSetting{textFormat, mdFormat}, args)
		},
	}

	cmd.PersistentFlags().StringVar(&args.InputSecondConfigFile, secondConfigFlag, "", "file path to the 2nd input config")
	cmd.MarkPersistentFlagRequired(secondConfigFlag)

	cmd.AddCommand(newDiffEndpointsCommand(args))
	cmd.AddCommand(newDiffSubnetsCommand(args))

	return cmd
}

func newDiffEndpointsCommand(args *InArgs) *cobra.Command {
	return &cobra.Command{
		Use:   "endpoints",
		Short: "Diff connectivity between endpoints",
		Long:  `reports changes in endpoint connectivity between two VPC configurations`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			args.AnalysisType = vpcmodel.EndpointsDiff
			return nil
		},
	}
}

func newDiffSubnetsCommand(args *InArgs) *cobra.Command {
	return &cobra.Command{
		Use:   "subnets",
		Short: "Diff connectivity between subnets",
		Long:  `reports changes in subnet connectivity between two VPC configurations`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			args.AnalysisType = vpcmodel.SubnetsDiff
			return nil
		},
	}
}
