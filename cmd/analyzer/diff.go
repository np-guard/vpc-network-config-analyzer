/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const secondConfigFlag = "vpc-config-second"

var supportedDiffFormats = []string{string(textFormat), string(mdFormat)}

func NewDiffCommand(args *InArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Diff connectivity postures as implied by two VPC configs",
		Long: `reports changes in connectivity (modified, added and removed connections)
		between two VPC configurations`,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if !slices.Contains(supportedDiffFormats, string(args.OutputFormat)) {
				return fmt.Errorf("output format for diff must be one of [%s]", strings.Join(supportedDiffFormats, separator))
			}
			return nil
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
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			args.AnalysisType = vpcmodel.EndpointsDiff
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
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			args.AnalysisType = vpcmodel.SubnetsDiff
			return analyze(args)
		},
	}
	return cmd
}
