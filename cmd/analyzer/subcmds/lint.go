/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"fmt"
	"github.com/spf13/cobra"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/linter"
)

const (
	enable  = "enable"
	disable = "disable"

	enableDisableUsage = "specified as linters names seperated by comma"
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
	validLintersNames := getListLintersName(linter.GetLintersNames())
	usageStr := "specific linters " + enableDisableUsage + " linters: " + validLintersNames
	cmd.Flags().StringSliceVar(&args.enableLinters, enable, []string{}, "enable "+usageStr)
	cmd.Flags().StringSliceVar(&args.disableLinters, disable, []string{}, "disable "+usageStr)
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
	enableList, _ := cmd.Flags().GetStringSlice("enable")
	disableList, _ := cmd.Flags().GetStringSlice("disable")
	_, _, err2 := linter.LinterExecute(multiConfigs.Configs(), enableList, disableList)
	return err2
}

func validateLintFlags(cmd *cobra.Command, args *inArgs) error {
	errFormat := validateFormatForMode(cmd.Use, []formatSetting{textFormat}, args)
	if errFormat != nil {
		return errFormat
	}

	enableList, errEnable1 := cmd.Flags().GetStringSlice("enable")
	if errEnable1 != nil {
		return errEnable1
	}
	disableList, errDisable1 := cmd.Flags().GetStringSlice("disable")
	if errDisable1 != nil {
		return errDisable1
	}
	errEnable2 := validLintersName(enableList, "enable")
	if errEnable2 != nil {
		return errEnable2
	}
	errDisable2 := validLintersName(disableList, "disable")
	if errDisable2 != nil {
		return errDisable2
	}
	if errBothEnableDisable := bothDisableAndEnable(enableList, disableList); errBothEnableDisable != nil {
		return errBothEnableDisable
	}
	return nil
}

func validLintersName(inputLinters []string, enableOrDisable string) error {
	validLintersNames := linter.GetLintersNames()
	if inputLinters == nil {
		return nil
	}
	for _, name := range inputLinters {
		if !validLintersNames[name] {
			return fmt.Errorf("%s in %s linters list does not exists.\t\nLegal linters: %s\n", name,
				enableOrDisable, getListLintersName(validLintersNames))
		}
	}
	return nil
}

func getListLintersName(lintersNames map[string]bool) string {
	legalNamesSlice := make([]string, len(lintersNames))
	i := 0
	for lintName := range lintersNames {
		legalNamesSlice[i] = lintName
		i++
	}
	return strings.Join(legalNamesSlice, ",")
}

func bothDisableAndEnable(enableLintersList, disableLintersList []string) error {
	for _, enable := range enableLintersList {
		for _, disable := range disableLintersList {
			if enable == disable {
				return fmt.Errorf("lint %s specified both as enable and disable. only one is possible", enable)
			}
		}
	}
	return nil
}
