/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import "github.com/spf13/cobra"

func NewReportCommand(args *InArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Report VPC connectivity as implied by the given cloud config",
		Long:  `reports VPC connectivity as implied by the given cloud configuration`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	cmd.Flags().BoolVarP(&args.Grouping, "grouping", "g", false, "whether to group together endpoints sharing the same connectivity")

	return cmd
}
