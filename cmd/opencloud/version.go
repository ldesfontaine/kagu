package main

import (
	"fmt"

	"github.com/ldesfontaine/opencloud/internal/kit/brand"
	"github.com/ldesfontaine/opencloud/internal/kit/version"
)

func runVersion() error {
	_, err := fmt.Println(brand.Command, version.String())
	return err
}
