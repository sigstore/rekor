// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"fmt"
	"math"
)

// Converts uint64 to int64 after checking bounds.
func SafeUint64ToInt64(u uint64) (int64, error) {
	if u > math.MaxInt64 {
		return 0, fmt.Errorf("value %d too large to convert to int64", u)
	}
	return int64(u), nil
}


func SafeInt64ToUint64(i int64) (uint64, error) {
	if i < 0 {
		return 0, fmt.Errorf("value %d is negative and cannot be converted to uint64", i)
	}
	return uint64(i), nil
}