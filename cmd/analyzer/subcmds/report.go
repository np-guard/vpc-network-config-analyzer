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

const (
	groupingFlag                = "grouping"
	loadBalancerAbstractionFlag = "load-balancer-abstraction"
)

func NewReportCommand(args *inArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Report VPC connectivity as implied by the given cloud config",
		Long:  `Report VPC connectivity as implied by the given cloud configuration`,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if args.grouping && args.outputFormat == jsonFormat {
				return fmt.Errorf("json output format is not supported with grouping")
			}
			return nil
		},
	}

	cmd.PersistentFlags().BoolVarP(&args.grouping, groupingFlag,
		"g", false, "whether to group together endpoints sharing the same connectivity")
	cmd.PersistentFlags().BoolVarP(&args.lbAbstraction, loadBalancerAbstractionFlag,
		"", true, "whether to abstract a load balancer to one endpoint")
	hideFlagsFromHelp(cmd, []string{loadBalancerAbstractionFlag})

	cmd.AddCommand(newReportEndpointsCommand(args))
	cmd.AddCommand(newReportSubnetsCommand(args))
	cmd.AddCommand(newReportSingleSubnetCommand(args))
	cmd.AddCommand(newReportRoutingCommand(args))

	return cmd
}

func newReportEndpointsCommand(args *inArgs) *cobra.Command {
	return &cobra.Command{
		Use:   "endpoints",
		Short: "Report VPC connectivity between endpoints",
		Long:  `reports VPC connectivity between endpoints as implied by the given cloud configuration`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return analysisVPCConfigs(cmd, args, vpcmodel.AllEndpoints)
		},
	}
}

func newReportSubnetsCommand(args *inArgs) *cobra.Command {
	return &cobra.Command{
		Use:   "subnets",
		Short: "Report VPC connectivity between subnets",
		Long:  `reports VPC connectivity between subnets as implied by the given cloud configuration`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return analysisVPCConfigs(cmd, args, vpcmodel.AllSubnets)
		},
	}
}

func newReportSingleSubnetCommand(args *inArgs) *cobra.Command {
	const SingleSubnetCmd = "single-subnet"
	return &cobra.Command{
		Use:   SingleSubnetCmd,
		Short: "Report VPC connectivity per subnet",
		Long:  `reports VPC connectivity per subnet as implied by the given cloud configuration`,
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			if args.grouping {
				return fmt.Errorf("currently single-subnet analysis type does not support grouping")
			}
			return validateFormatForMode(SingleSubnetCmd, []formatSetting{textFormat}, args)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return analysisVPCConfigs(cmd, args, vpcmodel.SingleSubnet)
		},
	}
}

func newReportRoutingCommand(args *inArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "routing",
		Short: "Report VPC routing paths between given endpoints",
		Long:  `reports VPC routing paths between given endpoints as implied by the given cloud configuration`,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return routingAnalysis(args)
		},
	}
	cmd.Flags().StringVar(&args.eSrc, srcFlag, "", "source "+srcDstUsage)
	cmd.Flags().StringVar(&args.eDst, dstFlag, "", "destination "+srcDstUsage)

	return cmd
}

func hideFlagsFromHelp(cmd *cobra.Command, flags []string) {
	cmd.SetHelpFunc(func(command *cobra.Command, strings []string) {
		err := markFlagsHidden(command, flags)
		if err != nil {
			// Do not know what to do with the error
			return
		}
		command.Parent().HelpFunc()(command, strings)
	})
	cmd.SetUsageFunc(func(command *cobra.Command) error {
		err := markFlagsHidden(command, flags)
		if err != nil {
			return err
		}
		// calling:
		// command.Parent().UsageFunc()(command)
		// gives infinite recursive call. the following works:
		cmd.SetUsageFunc(nil)
		return cmd.UsageFunc()(command)
	})
}
func markFlagsHidden(command *cobra.Command, flags []string) error {
	for _, flag := range flags {
		if err := command.Flags().MarkHidden(flag); err != nil {
			return err
		}
	}
	return nil
}
