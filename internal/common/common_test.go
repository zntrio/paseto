// Licensed to SolID under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. SolID licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package common

import (
	"reflect"
	"testing"
)

func TestPreAuthenticationEncoding(t *testing.T) {
	type args struct {
		pieces [][]byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "empty",
			args: args{
				pieces: nil,
			},
			want: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "one",
			args: args{
				pieces: [][]byte{
					[]byte("test"),
				},
			},
			want: []byte{
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Count
				0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Length
				't', 'e', 's', 't',
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PreAuthenticationEncoding(tt.args.pieces...)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PreAuthenticationEncoding() = %v, want %v", got, tt.want)
			}
		})
	}
}
