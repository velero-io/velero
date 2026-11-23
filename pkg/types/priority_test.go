/*
Copyright The Velero Contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringOfPriorities(t *testing.T) {
	priority := Priorities{
		HighPriorities: []string{"high"},
	}
	assert.Equal(t, "high", priority.String())

	priority = Priorities{
		HighPriorities: []string{"high"},
		LowPriorities:  []string{"low"},
	}
	assert.Equal(t, "high,-,low", priority.String())
}

func TestSetOfPriority(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		priorities Priorities
		hasErr     bool
	}{
		{
			name:       "empty input",
			input:      "",
			priorities: Priorities{},
			hasErr:     false,
		},
		{
			name:  "only high priorities",
			input: "p0",
			priorities: Priorities{
				HighPriorities: []string{"p0"},
			},
			hasErr: false,
		},
		{
			name:  "only low priorities",
			input: "-,p9",
			priorities: Priorities{
				LowPriorities: []string{"p9"},
			},
			hasErr: false,
		},
		{
			name:       "only separator",
			input:      "-",
			priorities: Priorities{},
			hasErr:     false,
		},
		{
			name:       "multiple separators",
			input:      "-,-",
			priorities: Priorities{},
			hasErr:     true,
		},
		{
			name:  "contain both high and low priorities",
			input: "p0,p1,p2,-,p9",
			priorities: Priorities{
				HighPriorities: []string{"p0", "p1", "p2"},
				LowPriorities:  []string{"p9"},
			},
			hasErr: false,
		},
		{
			name:  "end with separator",
			input: "p0,-",
			priorities: Priorities{
				HighPriorities: []string{"p0"},
			},
			hasErr: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := Priorities{}
			err := p.Set(c.input)
			if c.hasErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, c.priorities, p)
		})
	}
}

func TestSetDoesNotLeaveSpareCapacity(t *testing.T) {
	for input, wantString := range map[string]string{"p0,p1,-,p8,p9": "p0,p1,-,p8,p9", "p0,-": "p0"} {
		t.Run(input, func(t *testing.T) {
			p := Priorities{}
			require.NoError(t, p.Set(input))
			assert.Equal(t, len(p.HighPriorities), cap(p.HighPriorities))

			low := append([]string(nil), p.LowPriorities...)
			_ = append(p.HighPriorities, "x", "y", "z")
			assert.Equal(t, low, p.LowPriorities, "appending to HighPriorities changed LowPriorities")
			assert.Equal(t, wantString, p.String())
		})
	}
}
