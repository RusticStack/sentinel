package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDescribe(t *testing.T) {
	assert.Contains(t, describe(), "b05")
}
