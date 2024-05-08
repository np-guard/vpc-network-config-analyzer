/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"fmt"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/netp"
	"github.com/spf13/cobra"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const (
	srcFlag        = "src"
	dstFlag        = "dst"
	protocolFlag   = "protocol"
	srcMinPortFlag = "src-min-port"
	srcMaxPortFlag = "src-max-port"
	dstMinPortFlag = "dst-min-port"
	dstMaxPortFlag = "dst-max-port"

	srcDstUsage = "endpoint for explanation; can be specified as a VSI name/CRN or an internal/external IP-address/CIDR;\n" +
		"VSI name can be specified as <vsi-name> or  <vpc-name>/<vsi-name>"
)

func NewExplainCommand(args *InArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Explain connectivity between two endpoints",
		Long:  `explains how the given cloud configuration affects connectivity between two endpoints`,
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return validateExplainFlags(cmd, args)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			args.AnalysisType = vpcmodel.Explain
			return nil
		},
	}

	cmd.Flags().StringVar(&args.ESrc, srcFlag, "", "source "+srcDstUsage)
	cmd.Flags().StringVar(&args.EDst, dstFlag, "", "destination "+srcDstUsage)
	cmd.Flags().Var(&args.EProtocol, protocolFlag, "protocol for connection description")
	cmd.Flags().Int64Var(&args.ESrcMinPort, srcMinPortFlag, netp.MinPort, "minimum source port for connection description")
	cmd.Flags().Int64Var(&args.ESrcMaxPort, srcMaxPortFlag, netp.MaxPort, "maximum source port for connection description")
	cmd.Flags().Int64Var(&args.EDstMinPort, dstMinPortFlag, netp.MinPort, "minimum destination port for connection description")
	cmd.Flags().Int64Var(&args.EDstMaxPort, dstMaxPortFlag, netp.MaxPort, "maximum destination port for connection description")

	cmd.MarkFlagRequired(srcFlag)
	cmd.MarkFlagRequired(dstFlag)

	return cmd
}

func portInRange(port int64) bool {
	if port > connection.MaxPort || port < connection.MinPort {
		return false
	}

	return true
}

func minMaxValidity(minPort, maxPort int64, minPortName, maxPortName string) error {
	if minPort > maxPort {
		return fmt.Errorf("%s %d must not be larger than %s %d", minPortName, minPort, maxPortName, maxPort)
	}

	return nil
}

func flagSet(cmd *cobra.Command, flagName string) bool {
	flag := cmd.Flags().Lookup(flagName)
	if flag == nil {
		return false
	}
	return flag.Changed
}

func validateExplainFlags(cmd *cobra.Command, args *InArgs) error {
	err := validateFormatForMode("explain", []formatSetting{textFormat, debugFormat}, args)
	if err != nil {
		return err
	}

	if args.EProtocol == "" {
		if flagSet(cmd, srcMinPortFlag) || flagSet(cmd, srcMaxPortFlag) ||
			flagSet(cmd, dstMinPortFlag) || flagSet(cmd, dstMaxPortFlag) {
			return fmt.Errorf("protocol must be specified when specifying ports")
		}
	}

	err = minMaxValidity(args.ESrcMinPort, args.ESrcMaxPort, srcMinPortFlag, srcMaxPortFlag)
	if err != nil {
		return err
	}
	err = minMaxValidity(args.EDstMinPort, args.EDstMaxPort, dstMinPortFlag, dstMaxPortFlag)
	if err != nil {
		return err
	}

	if !portInRange(args.ESrcMinPort) || !portInRange(args.ESrcMaxPort) ||
		!portInRange(args.EDstMinPort) || !portInRange(args.EDstMaxPort) {
		return fmt.Errorf("port number must be in between %d, %d, inclusive",
			connection.MinPort, connection.MaxPort)
	}

	return nil
}
