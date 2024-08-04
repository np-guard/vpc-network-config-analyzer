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
	cmd.Flags().StringVar(&args.enableLints, enable, "", "enable "+usageStr)
	cmd.Flags().StringVar(&args.disableLints, disable, "", "disable "+usageStr)
	return cmd
}

func lintVPCConfigs(cmd *cobra.Command, inArgs *inArgs) error {
	cmd.SilenceUsage = true  // if we got this far, flags are syntactically correct, so no need to print usage
	cmd.SilenceErrors = true // also, error will be printed to logger in main(), so no need for cobra to also print it

	multiConfigs, err1 := buildConfigs(inArgs)
	if err1 != nil {
		return err1
	}
	_, _, err2 := linter.LinterExecute(multiConfigs.Configs())
	return err2
}

func validateLintFlags(cmd *cobra.Command, args *inArgs) error {
	err := validateFormatForMode(cmd.Use, []formatSetting{textFormat}, args)
	if err != nil {
		return err
	}

	enableLintsStrings := strings.ReplaceAll(args.enableLints, " ", "")
	disableLintsStrings := strings.ReplaceAll(args.enableLints, " ", "")
	enableLintersList := strings.Split(enableLintsStrings, ",")
	disableLintersList := strings.Split(disableLintsStrings, ",")
	validLintersNames := linter.GetLintersNames()
	if errEnable := validLintersName(enableLintersList, validLintersNames, "enable"); errEnable != nil {
		return errEnable
	}
	if errDisable := validLintersName(disableLintersList, validLintersNames, "disable"); errDisable != nil {
		return errDisable
	}
	return nil
}

func validLintersName(inputLinterNames []string, validLintersNames map[string]bool, enableOrDisable string) error {
	for _, name := range inputLinterNames {
		if !validLintersNames[name] {
			return fmt.Errorf("%s in %s linters list does not exists.\t\nLegal names: %s\n", name,
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
