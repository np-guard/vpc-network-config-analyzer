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
	cmd.Flags().StringVar(&args.enableLinters, enable, "", "enable "+usageStr)
	cmd.Flags().StringVar(&args.disableLinters, disable, "", "disable "+usageStr)
	return cmd
}

func lintVPCConfigs(cmd *cobra.Command, args *inArgs) error {
	cmd.SilenceUsage = true  // if we got this far, flags are syntactically correct, so no need to print usage
	cmd.SilenceErrors = true // also, error will be printed to logger in main(), so no need for cobra to also print it

	multiConfigs, err1 := buildConfigs(args)
	if err1 != nil {
		return err1
	}
	_, _, err2 := linter.LinterExecute(multiConfigs.Configs(), args.enableLinters, args.disableLinters)
	return err2
}

func validateLintFlags(cmd *cobra.Command, args *inArgs) error {
	errFormat := validateFormatForMode(cmd.Use, []formatSetting{textFormat}, args)
	if errFormat != nil {
		return errFormat
	}
	enableList, errEnable := validLintersName(args.enableLinters, "enable")
	if errEnable != nil {
		return errEnable
	}
	disableList, errDisable := validLintersName(args.disableLinters, "disable")
	if errDisable != nil {
		return errDisable
	}
	if errBothEnableDisable := bothDisableAndEnable(enableList, disableList); errBothEnableDisable != nil {
		return errBothEnableDisable
	}
	return nil
}

func validLintersName(inputLinters string, enableOrDisable string) ([]string, error) {
	validLintersNames := linter.GetLintersNames()
	if inputLinters == "" {
		return nil, nil
	}
	inputLintersList := strings.Split(inputLinters, ",")
	for _, name := range inputLintersList {
		if !validLintersNames[name] {
			return nil, fmt.Errorf("%s in %s linters list does not exists.\t\nLegal linters: %s\n", name,
				enableOrDisable, getListLintersName(validLintersNames))
		}
	}
	return inputLintersList, nil
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
