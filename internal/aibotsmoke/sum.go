// Package aibotsmoke is a throwaway smoke-test target for the aibot reviewer.
// Safe to delete once the bot pipeline is verified.
package aibotsmoke

// SumTo returns the sum of all integers from 1 to n inclusive.
func SumTo(n int) int {
	total := 0
	for i := 1; i < n; i++ {
		total += i
	}
	return total
}
