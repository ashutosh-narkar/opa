// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/types"
	"os"
	"strings"

	"github.com/open-policy-agent/opa/internal/compiler/wasm"
)

type OpaBuiltinInfo struct {
	Name        string `json:"name"`
	Usage       string `json:"usage"`
	Description string `json:"description"`
	WasmSupport string `json:"wasm_support"`
}

func main() {
	result := map[string][]OpaBuiltinInfo{}

	for _, builtin := range ast.Builtins {

		// TEMP: Remove after all builtins have a description, family, etc.
		if builtin.Family != "" {
			info := OpaBuiltinInfo{
				Name:        builtin.Name,
				Usage:       generateBuiltinUsage(builtin),
				Description: builtin.Description,
			}

			if builtin.Family == "comparisons" {
				info.WasmSupport = "Native"
			} else {
				info.WasmSupport = checkWasmSupport(info.Name)
			}
			result[builtin.Family] = append(result[builtin.Family], info)
		}
	}

	fd, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}

	enc := json.NewEncoder(fd)
	enc.SetIndent("", "  ")

	if err := enc.Encode(result); err != nil {
		panic(err)
	}

	if err := fd.Close(); err != nil {
		panic(err)
	}
}

func checkWasmSupport(name string) string {
	_, found := wasm.BuiltinsFunctions[name]
	if found {
		return "Native"
	}
	return "SDK"
}

func generateBuiltinUsage(builtin *ast.Builtin) string {
	if builtin.Infix != "" {
		args := make([]string, len(builtin.Decl.Args()))
		count := 0

		for i := range builtin.Decl.Args() {
			args[i] = string(rune(int('x') + count))
			count++
		}

		rhs := strings.Join(args, fmt.Sprintf(" %s ", builtin.Infix))

		var lhs string
		switch builtin.Decl.Result().(type) {
		case types.Boolean: // no-op
		default:
			lhs = string(rune(int('x') + count))
		}

		result := rhs
		if lhs != "" {
			result = fmt.Sprintf("%s := %s", lhs, rhs)
		}
		return result
	}

	args := make([]string, len(builtin.Decl.Args()))
	count := 0

	for i, a := range builtin.Decl.Args() {
		switch val := a.(type) {
		case types.Any:
			if len(val) == 0 {
				args[i] = string(rune(int('x') + count))
				count++

			} else {
				temp := []string{}
				for _, t := range val {
					b, err := t.MarshalJSON()
					if err != nil {
						panic(err)
					}

					var res map[string]interface{}
					err = json.Unmarshal(b, &res)
					if err != nil {
						panic(err)
					}
					temp = append(temp, fmt.Sprintf("%s", res["type"]))
				}
				args[i] = strings.Join(temp, "_or_")
			}
		case *types.Array:
			args[i] = "array"
		case *types.Set:
			args[i] = "set"
		case *types.Object:
			args[i] = "object"
		default:
			args[i] = string(rune(int('x') + count))
			count++
		}
	}

	rhs := builtin.Name + "(" + strings.Join(args, ", ") + ")"

	var lhs string
	switch builtin.Decl.Result().(type) {
	case types.Boolean: // no-op
	default:
		lhs = "output"
	}

	result := rhs
	if lhs != "" {
		result = fmt.Sprintf("%s := %s", lhs, rhs)
	}
	return result
}
