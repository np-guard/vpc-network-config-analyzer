/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewReportCommand(args *InArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Report VPC connectivity as implied by the given cloud config",
		Long:  `reports VPC connectivity as implied by the given cloud configuration`,
		Args: func(cmd *cobra.Command, args []string) error {
			return cobra.NoArgs(cmd, args)
		},
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if args.Grouping && args.OutputFormat == jsonFormat {
				return fmt.Errorf("json output format is not supported with grouping")
			}
			return nil
		},
		Run: func(_ *cobra.Command, _ []string) {},
	}

	cmd.PersistentFlags().BoolVarP(&args.Grouping, "grouping", "g", false, "whether to group together endpoints sharing the same connectivity")

	cmd.AddCommand(NewEndpointsCommand(args))
	cmd.AddCommand(NewSubnetsCommand(args))
	cmd.AddCommand(NewSingleSubnetCommand(args))

	return cmd
}

func NewEndpointsCommand(args *InArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "endpoints",
		Short: "Report VPC connectivity between endpoints",
		Long:  `reports VPC connectivity between endpoints as implied by the given cloud configuration`,
		Args: func(cmd *cobra.Command, args []string) error {
			return cobra.NoArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			args.AnalysisType = allEndpoints
			return analyze(args)
		},
	}
	return cmd
}

func NewSubnetsCommand(args *InArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "subnets",
		Short: "Report VPC connectivity between subnets",
		Long:  `reports VPC connectivity between subnets as implied by the given cloud configuration`,
		Args: func(cmd *cobra.Command, args []string) error {
			return cobra.NoArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			args.AnalysisType = allSubnets
			return analyze(args)
		},
	}
	return cmd
}

func NewSingleSubnetCommand(args *InArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "singleSubnet",
		Short: "Report VPC connectivity per subnet",
		Long:  `reports VPC connectivity per subnet as implied by the given cloud configuration`,
		Args: func(cmd *cobra.Command, args []string) error {
			return cobra.NoArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if args.Grouping {
				return fmt.Errorf("currently single-subnet analysis type does not support grouping")
			}
			args.AnalysisType = singleSubnet
			return analyze(args)
		},
	}
	return cmd
}
