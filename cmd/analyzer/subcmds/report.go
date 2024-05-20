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

func NewReportCommand(args *InArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Report VPC connectivity as implied by the given cloud config",
		Long:  `Report VPC connectivity as implied by the given cloud configuration`,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if args.Grouping && args.OutputFormat == jsonFormat {
				return fmt.Errorf("json output format is not supported with grouping")
			}
			return nil
		},
	}

	cmd.PersistentFlags().BoolVarP(&args.Grouping, "grouping", "g", false, "whether to group together endpoints sharing the same connectivity")

	cmd.AddCommand(newReportEndpointsCommand(args))
	cmd.AddCommand(newReportSubnetsCommand(args))
	cmd.AddCommand(newReportSingleSubnetCommand(args))

	return cmd
}

func newReportEndpointsCommand(args *InArgs) *cobra.Command {
	return &cobra.Command{
		Use:   "endpoints",
		Short: "Report VPC connectivity between endpoints",
		Long:  `reports VPC connectivity between endpoints as implied by the given cloud configuration`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			args.AnalysisType = vpcmodel.AllEndpoints
			return nil
		},
	}
}

func newReportSubnetsCommand(args *InArgs) *cobra.Command {
	return &cobra.Command{
		Use:   "subnets",
		Short: "Report VPC connectivity between subnets",
		Long:  `reports VPC connectivity between subnets as implied by the given cloud configuration`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			args.AnalysisType = vpcmodel.AllSubnets
			return nil
		},
	}
}

func newReportSingleSubnetCommand(args *InArgs) *cobra.Command {
	const SingleSubnetCmd = "single-subnet"
	return &cobra.Command{
		Use:   SingleSubnetCmd,
		Short: "Report VPC connectivity per subnet",
		Long:  `reports VPC connectivity per subnet as implied by the given cloud configuration`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if args.Grouping {
				return fmt.Errorf("currently single-subnet analysis type does not support grouping")
			}
			if err := validateFormatForMode(SingleSubnetCmd, []formatSetting{textFormat}, args); err != nil {
				return err
			}
			args.AnalysisType = vpcmodel.SingleSubnet
			return nil
		},
	}
}
