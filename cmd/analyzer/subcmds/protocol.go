/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/netp"
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
	return fmt.Errorf(mustBeOneOf(allowedProtocols))
}

func (ps *protocolSetting) Type() string {
	return "string"
}
