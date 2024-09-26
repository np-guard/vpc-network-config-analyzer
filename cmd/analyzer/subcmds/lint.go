/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/linter"
)

const (
	enable       = "enable"
	disable      = "disable"
	printAllFlag = "print-all"
)

func NewLintCommand(args *inArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lint",
		Short: "Run various checks for ensuring best-practices",
		Long:  `Execute various (configurable) linting and provides findings`,
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return validateLintFlags(cmd, args)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return lintVPCConfigs(cmd, args)
		},
	}
	validLintersNames := linter.ValidLintersNames()
	usageStr := " specific linters, specified as linter names separated by comma.\nlinters: " + validLintersNames
	cmd.Flags().StringSliceVar(&args.enableLinters, enable, []string{}, enable+usageStr)
	cmd.Flags().StringSliceVar(&args.disableLinters, disable, []string{}, disable+usageStr)
	cmd.Flags().BoolVar(&args.printAllLinters, printAllFlag, false, "print all findings (do not limit "+
		"findings of each linter to 3)")
	return cmd
}

func lintVPCConfigs(cmd *cobra.Command, args *inArgs) error {
	cmd.SilenceUsage = true  // if we got this far, flags are syntactically correct, so no need to print usage
	cmd.SilenceErrors = true // also, error will be printed to logger in main(), so no need for cobra to also print it

	multiConfigs, err1 := buildConfigs(args)
	if err1 != nil {
		return err1
	}
	// potential errors already handled
	_, err2 := linter.LinterExecute(multiConfigs.Configs(), args.printAllLinters,
		args.enableLinters, args.disableLinters)
	return err2
}

func validateLintFlags(cmd *cobra.Command, args *inArgs) error {
	errFormat := validateFormatForMode(cmd.Use, []formatSetting{textFormat}, args)
	if errFormat != nil {
		return errFormat
	}
	errEnable := validLintersName(args.enableLinters, enable)
	if errEnable != nil {
		return errEnable
	}
	errDisable := validLintersName(args.disableLinters, disable)
	if errDisable != nil {
		return errDisable
	}
	if errBothEnableDisable := bothDisableAndEnable(args); errBothEnableDisable != nil {
		return errBothEnableDisable
	}
	return nil
}

func validLintersName(inputLinters []string, enableOrDisable string) error {
	if inputLinters == nil {
		return nil
	}
	for _, name := range inputLinters {
		if !linter.IsValidLintersNames(name) {
			return fmt.Errorf("%s in %s linters list does not exists.\t\nLegal linters: %s", name,
				enableOrDisable, linter.ValidLintersNames())
		}
	}
	return nil
}

func bothDisableAndEnable(args *inArgs) error {
	for _, enable := range args.enableLinters {
		if slices.Contains(args.disableLinters, enable) {
			return fmt.Errorf("lint %s specified both as enable and disable. only one is possible", enable)
		}
	}
	return nil
}
