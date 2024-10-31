/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/np-guard/models/pkg/netp"

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
	detailFlag     = "detail"

	srcDstUsage = "endpoint; can be specified as a VSI/subnet name/CRN or an internal/external IP-address/CIDR;\n" +
		"VSI/subnet name can be specified as <vsi-name/subnet-name> or as <vpc-name>/<vsi-name/subnet-name>"
)

func NewExplainCommand(args *inArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Explain connectivity between two endpoints",
		Long:  `Explain how the given cloud configuration affects connectivity between two endpoints`,
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return validateExplainFlags(cmd, args)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			args.explanationArgs = vpcmodel.NewExplanationArgs(args.eSrc, args.eDst, args.eProtocol.String(),
				args.eSrcMinPort, args.eSrcMaxPort, args.eDstMinPort, args.eDstMaxPort, args.detailExplain)
			return analysisVPCConfigs(cmd, args, vpcmodel.Explain)
		},
	}

	cmd.Flags().StringVar(&args.eSrc, srcFlag, "", "source "+srcDstUsage)
	cmd.Flags().StringVar(&args.eDst, dstFlag, "", "destination "+srcDstUsage)
	cmd.Flags().Var(&args.eProtocol, protocolFlag, "protocol for connection description")
	cmd.Flags().Int64Var(&args.eSrcMinPort, srcMinPortFlag, netp.MinPort, "minimum source port for connection description")
	cmd.Flags().Int64Var(&args.eSrcMaxPort, srcMaxPortFlag, netp.MaxPort, "maximum source port for connection description")
	cmd.Flags().Int64Var(&args.eDstMinPort, dstMinPortFlag, netp.MinPort, "minimum destination port for connection description")
	cmd.Flags().Int64Var(&args.eDstMaxPort, dstMaxPortFlag, netp.MaxPort, "maximum destination port for connection description")
	cmd.Flags().BoolVar(&args.detailExplain, detailFlag, false, "adds a section with a list of all relevant allow/deny rules")

	_ = cmd.MarkFlagRequired(srcFlag)
	_ = cmd.MarkFlagRequired(dstFlag)
	cmd.Flags().SortFlags = false

	return cmd
}

func portInRange(port int64) bool {
	if port > netp.MaxPort || port < netp.MinPort {
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

func FlagSet(cmd *cobra.Command, flagName string) bool {
	flag := cmd.Flags().Lookup(flagName)
	if flag == nil {
		return false
	}
	return flag.Changed
}

func validateExplainFlags(cmd *cobra.Command, args *inArgs) error {
	err := validateFormatForMode(cmd.Use, []formatSetting{textFormat}, args)
	if err != nil {
		return err
	}

	if args.eProtocol == "" {
		if FlagSet(cmd, srcMinPortFlag) || FlagSet(cmd, srcMaxPortFlag) ||
			FlagSet(cmd, dstMinPortFlag) || FlagSet(cmd, dstMaxPortFlag) {
			return fmt.Errorf("protocol must be specified when specifying ports")
		}
	}

	err = minMaxValidity(args.eSrcMinPort, args.eSrcMaxPort, srcMinPortFlag, srcMaxPortFlag)
	if err != nil {
		return err
	}
	err = minMaxValidity(args.eDstMinPort, args.eDstMaxPort, dstMinPortFlag, dstMaxPortFlag)
	if err != nil {
		return err
	}

	if !portInRange(args.eSrcMinPort) || !portInRange(args.eSrcMaxPort) ||
		!portInRange(args.eDstMinPort) || !portInRange(args.eDstMaxPort) {
		return fmt.Errorf("port number must be in between %d, %d, inclusive",
			netp.MinPort, netp.MaxPort)
	}

	return nil
}
