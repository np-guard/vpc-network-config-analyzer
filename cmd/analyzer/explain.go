/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/netp"
	"github.com/spf13/cobra"
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

type protocolSetting netp.ProtocolString

func (ps *protocolSetting) String() string {
	return string(*ps)
}

func (ps *protocolSetting) Set(v string) error {
	allowedProtocols := []string{string(netp.ProtocolStringICMP), string(netp.ProtocolStringTCP), string(netp.ProtocolStringUDP)}
	v = strings.ToUpper(v)
	if slices.Contains(allowedProtocols, v) {
		*ps = protocolSetting(v)
		return nil
	}
	return fmt.Errorf(`must be one of [%s]`, strings.Join(allowedProtocols, ", "))
}

func (ps *protocolSetting) Type() string {
	return "string"
}

func NewExplainCommand(args *InArgs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Explain connectivity between two endpoints",
		Long:  `explains how the given cloud configuration affects connectivity between two endpoints`,
		Args: func(cmd *cobra.Command, args []string) error {
			return cobra.NoArgs(cmd, args)
		},
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			args.AnalysisType = explainMode
			return analyze(args)
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

func PortInRange(port int64) bool {
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

func validateArgs(cmd *cobra.Command, args *InArgs) error {
	if args.EProtocol == "" {
		if flagSet(cmd, srcMinPortFlag) || flagSet(cmd, srcMaxPortFlag) ||
			flagSet(cmd, dstMinPortFlag) || flagSet(cmd, dstMaxPortFlag) {
			return fmt.Errorf("protocol must be specified when specifying ports")
		}
	}

	err := minMaxValidity(args.ESrcMinPort, args.ESrcMaxPort, srcMinPortFlag, srcMaxPortFlag)
	if err != nil {
		return err
	}
	err = minMaxValidity(args.EDstMinPort, args.EDstMaxPort, dstMinPortFlag, dstMaxPortFlag)
	if err != nil {
		return err
	}

	if !PortInRange(args.ESrcMinPort) || !PortInRange(args.ESrcMaxPort) ||
		!PortInRange(args.EDstMinPort) || !PortInRange(args.EDstMaxPort) {
		return fmt.Errorf("port number must be in between %d, %d, inclusive",
			connection.MinPort, connection.MaxPort)
	}

	return nil
}
