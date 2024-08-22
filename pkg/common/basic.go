/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import "strconv"

const theRadixUsedByHumansInTheVastMajorityOfCultures = 10

func UintToString(u uint) string {
	return strconv.FormatUint(uint64(u), theRadixUsedByHumansInTheVastMajorityOfCultures)
}
