/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import "github.com/spf13/cobra"

func NewDiffCommand(args *InArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Diff connectivity postures as implied by two VPC configs",
		Long: `reports changes in connectivity (modified, added and removed connections)
		between two VPC configurations`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	cmd.Flags().StringVar(&args.InputSecondConfigFile, "vpc-config-second", "", "file path to the 2nd input config")

	return cmd
}
