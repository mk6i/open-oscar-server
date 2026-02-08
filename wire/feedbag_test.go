package wire

import (
	"math"
	"testing"
)

func TestRandItemID(t *testing.T) {
	tt := []struct {
		name        string
		randInt     func(n int) int
		items       FeedbagItems
		want        uint16
		description string
	}{
		{
			name: "empty items list returns random ID",
			randInt: func(n int) int {
				return 1000
			},
			items:       FeedbagItems{},
			want:        1000,
			description: "When no items exist, should return the random number generated",
		},
		{
			name: "finds next available ID when starting ID conflicts with ItemID",
			randInt: func(n int) int {
				return 100
			},
			items: FeedbagItems{
				{ItemID: 100, GroupID: 1},
				{ItemID: 101, GroupID: 1},
			},
			want:        102,
			description: "Should skip 100 and 101, return 102",
		},
		{
			name: "finds next available ID when starting ID conflicts with GroupID",
			randInt: func(n int) int {
				return 50
			},
			items: FeedbagItems{
				{ItemID: 1, GroupID: 50},
				{ItemID: 2, GroupID: 51},
			},
			want:        52,
			description: "Should skip 50 (GroupID) and 51 (GroupID), return 52",
		},
		{
			name: "wraps around and skips 0 to find next available ID",
			randInt: func(n int) int {
				return math.MaxUint16 - 2
			},
			items: FeedbagItems{
				{ItemID: math.MaxUint16 - 2, GroupID: 1},
				{ItemID: math.MaxUint16 - 1, GroupID: 1},
				{ItemID: math.MaxUint16, GroupID: 1},
			},
			want:        2,
			description: "When wrapping around, skips 0 (always skipped) and 1 (if conflicts), returns 2",
		},
		{
			name: "skips 0 when starting from 0 and finds next available",
			randInt: func(n int) int {
				return 0
			},
			items:       FeedbagItems{},
			want:        1,
			description: "When starting from 0, skips 0 (always skipped) and returns 1",
		},
		{
			name: "returns 0 when all IDs are taken",
			randInt: func(n int) int {
				return 100
			},
			items: func() FeedbagItems {
				// Create items that cover all possible IDs
				items := make(FeedbagItems, 0, math.MaxUint16+1)
				for i := 0; i <= math.MaxUint16; i++ {
					items = append(items, FeedbagItem{
						ItemID:  uint16(i),
						GroupID: uint16(i),
					})
				}
				return items
			}(),
			want:        0,
			description: "When all IDs are taken, should return 0",
		},
		{
			name: "finds ID that conflicts with both ItemID and GroupID",
			randInt: func(n int) int {
				return 200
			},
			items: FeedbagItems{
				{ItemID: 200, GroupID: 201},
				{ItemID: 201, GroupID: 200},
			},
			want:        202,
			description: "Should skip 200 (ItemID) and 201 (both ItemID and GroupID), return 202",
		},
		{
			name: "finds available ID immediately when no conflicts",
			randInt: func(n int) int {
				return 500
			},
			items: FeedbagItems{
				{ItemID: 100, GroupID: 1},
				{ItemID: 200, GroupID: 2},
				{ItemID: 300, GroupID: 3},
			},
			want:        500,
			description: "When random ID has no conflicts, should return it immediately",
		},
		{
			name: "handles single conflict and finds next",
			randInt: func(n int) int {
				return 42
			},
			items: FeedbagItems{
				{ItemID: 42, GroupID: 1},
			},
			want:        43,
			description: "Should skip 42 and return 43",
		},
		{
			name: "finds ID before starting point when wrapping",
			randInt: func(n int) int {
				return 5
			},
			items: FeedbagItems{
				{ItemID: 5, GroupID: 1},
				{ItemID: 6, GroupID: 1},
				{ItemID: 7, GroupID: 1},
			},
			want:        8,
			description: "Should skip 5, 6, 7 and return 8",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.items.randItemID(tc.randInt)
			if got != tc.want {
				t.Errorf("randItemID() = %d, want %d. %s", got, tc.want, tc.description)
			}
		})
	}
}
