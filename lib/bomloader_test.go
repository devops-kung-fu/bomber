package lib

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_removeDuplicates(t *testing.T) {
	test := []string{"A", "B", "C", "D"}

	result := removeDuplicates(test)
	assert.Len(t, result, 4)

	test = append(test, "B")
	result = removeDuplicates(test)
	assert.Len(t, result, 4)
}
