/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/cloud-resource-collector/pkg/factory"
)

type provider string

var allProviders = []string{
	factory.IBM,
}

func (p *provider) String() string {
	return string(*p)
}

func (p *provider) Set(v string) error {
	v = strings.ToLower(v)
	if slices.Contains(allProviders, v) {
		*p = provider(v)
		return nil
	}
	return fmt.Errorf("%s", mustBeOneOf(allProviders))
}

func (p *provider) Type() string {
	return stringType
}
