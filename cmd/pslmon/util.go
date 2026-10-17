package main

import (
	"io"
	"strings"
)

func ioCopy(dst *strings.Builder, src io.Reader, limit int64) (int64, error) {
	return io.Copy(dst, io.LimitReader(src, limit))
}
