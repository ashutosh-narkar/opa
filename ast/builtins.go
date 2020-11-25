// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

import (
	"strings"

	"github.com/open-policy-agent/opa/types"
)

// Builtins is the registry of built-in functions supported by OPA.
// Call RegisterBuiltin to add a new built-in.
var Builtins []*Builtin

// RegisterBuiltin adds a new built-in function to the registry.
func RegisterBuiltin(b *Builtin) {
	Builtins = append(Builtins, b)
	BuiltinMap[b.Name] = b
	if len(b.Infix) > 0 {
		BuiltinMap[b.Infix] = b
	}
}

// DefaultBuiltins is the registry of built-in functions supported in OPA
// by default. When adding a new built-in function to OPA, update this
// list.
var DefaultBuiltins = [...]*Builtin{
	// Unification/equality ("=")
	Equality,

	// Assignment (":=")
	Assign,

	// Comparisons
	GreaterThan,
	GreaterThanEq,
	LessThan,
	LessThanEq,
	NotEqual,
	Equal,

	// Arithmetic
	Plus,
	Minus,
	Multiply,
	Divide,
	Rem,
	Round,
	Abs,

	// Bitwise Arithmetic
	BitsOr,
	BitsAnd,
	BitsNegate,
	BitsXOr,
	BitsShiftLeft,
	BitsShiftRight,

	// Binary
	And,
	Or,

	// Aggregates
	Count,
	Sum,
	Product,
	Max,
	Min,
	Any,
	All,

	// Arrays
	ArrayConcat,
	ArraySlice,

	// Conversions
	ToNumber,

	// Casts (DEPRECATED)
	CastObject,
	CastNull,
	CastBoolean,
	CastString,
	CastSet,
	CastArray,

	// Regular Expressions
	RegexIsValid,
	RegexMatch,
	RegexMatchDeprecated,
	RegexSplit,
	GlobsMatch,
	RegexTemplateMatch,
	RegexFind,
	RegexFindAllStringSubmatch,

	// Sets
	SetDiff,
	Intersection,
	Union,

	// Strings
	Concat,
	Contains,
	StartsWith,
	EndsWith,
	FormatInt,
	IndexOf,
	Substring,
	Lower,
	Upper,
	Split,
	Replace,
	ReplaceN,
	Trim,
	TrimLeft,
	TrimPrefix,
	TrimRight,
	TrimSuffix,
	TrimSpace,
	Sprintf,

	// Numbers
	NumbersRange,

	// Encoding
	JSONMarshal,
	JSONUnmarshal,
	JSONIsValid,
	Base64Encode,
	Base64Decode,
	Base64IsValid,
	Base64UrlEncode,
	Base64UrlEncodeNoPad,
	Base64UrlDecode,
	URLQueryDecode,
	URLQueryEncode,
	URLQueryEncodeObject,
	URLQueryDecodeObject,
	YAMLMarshal,
	YAMLUnmarshal,
	YAMLIsValid,
	HexEncode,
	HexDecode,

	// Object Manipulation
	ObjectGet,
	ObjectRemove,
	ObjectUnion,
	ObjectFilter,

	// JSON Object Manipulation
	JSONFilter,
	JSONRemove,

	// Tokens
	JWTDecode,
	JWTVerifyRS256,
	JWTVerifyRS384,
	JWTVerifyRS512,
	JWTVerifyPS256,
	JWTVerifyPS384,
	JWTVerifyPS512,
	JWTVerifyES256,
	JWTVerifyES384,
	JWTVerifyES512,
	JWTVerifyHS256,
	JWTVerifyHS384,
	JWTVerifyHS512,
	JWTDecodeVerify,
	JWTEncodeSignRaw,
	JWTEncodeSign,

	// Time
	NowNanos,
	ParseNanos,
	ParseRFC3339Nanos,
	ParseDurationNanos,
	Date,
	Clock,
	Weekday,
	AddDate,

	// Crypto
	CryptoX509ParseCertificates,
	CryptoMd5,
	CryptoSha1,
	CryptoSha256,
	CryptoX509ParseCertificateRequest,

	// Graphs
	WalkBuiltin,
	ReachableBuiltin,

	// Sort
	Sort,

	// Types
	IsNumber,
	IsString,
	IsBoolean,
	IsArray,
	IsSet,
	IsObject,
	IsNull,
	TypeNameBuiltin,

	// HTTP
	HTTPSend,

	// Rego
	RegoParseModule,

	// OPA
	OPARuntime,

	// Tracing
	Trace,

	// CIDR
	NetCIDROverlap,
	NetCIDRIntersects,
	NetCIDRContains,
	NetCIDRContainsMatches,
	NetCIDRExpand,
	NetCIDRMerge,

	// Glob
	GlobMatch,
	GlobQuoteMeta,

	// Units
	UnitsParseBytes,

	// UUIDs
	UUIDRFC4122,

	//SemVers
	SemVerIsValid,
	SemVerCompare,
}

// BuiltinMap provides a convenient mapping of built-in names to
// built-in definitions.
var BuiltinMap map[string]*Builtin

// IgnoreDuringPartialEval is a set of built-in functions that should not be
// evaluated during partial evaluation. These functions are not partially
// evaluated because they are not pure.
var IgnoreDuringPartialEval = []*Builtin{
	NowNanos,
	HTTPSend,
	UUIDRFC4122,
}

/**
 * Unification
 */

// Equality represents the "=" operator.
var Equality = &Builtin{
	Name:  "eq",
	Infix: "=",
	Decl: types.NewFunction(
		types.Args(types.A, types.A),
		types.B,
	),
}

/**
 * Assignment
 */

// Assign represents the assignment (":=") operator.
var Assign = &Builtin{
	Name:  "assign",
	Infix: ":=",
	Decl: types.NewFunction(
		types.Args(types.A, types.A),
		types.B,
	),
}

/**
 * Comparisons
 */

// GreaterThan represents the ">" comparison operator.
var GreaterThan = &Builtin{
	Name: "gt",
	Decl: types.NewFunction(
		types.Args(types.A, types.A),
		types.B,
	),
	Family:      "comparisons",
	Description: "``x`` is greater than ``y``",
	Infix:       ">",
}

// GreaterThanEq represents the ">=" comparison operator.
var GreaterThanEq = &Builtin{
	Name: "gte",
	Decl: types.NewFunction(
		types.Args(types.A, types.A),
		types.B,
	),
	Family:      "comparisons",
	Description: "``x`` is greater than or equal to ``y``",
	Infix:       ">=",
}

// LessThan represents the "<" comparison operator.
var LessThan = &Builtin{
	Name: "lt",
	Decl: types.NewFunction(
		types.Args(types.A, types.A),
		types.B,
	),
	Family:      "comparisons",
	Description: "``x`` is less than ``y``",
	Infix:       "<",
}

// LessThanEq represents the "<=" comparison operator.
var LessThanEq = &Builtin{
	Name: "lte",
	Decl: types.NewFunction(
		types.Args(types.A, types.A),
		types.B,
	),
	Family:      "comparisons",
	Description: "``x`` is less than or equal to ``y``",
	Infix:       "<=",
}

// NotEqual represents the "!=" comparison operator.
var NotEqual = &Builtin{
	Name: "neq",
	Decl: types.NewFunction(
		types.Args(types.A, types.A),
		types.B,
	),
	Family:      "comparisons",
	Description: "``x`` is not equal to ``y``",
	Infix:       "!=",
}

// Equal represents the "==" comparison operator.
var Equal = &Builtin{
	Name: "equal",
	Decl: types.NewFunction(
		types.Args(types.A, types.A),
		types.B,
	),
	Family:      "comparisons",
	Description: "``x`` is equal to ``y``",
	Infix:       "==",
}

/**
 * Arithmetic
 */

// Plus adds two numbers together.
var Plus = &Builtin{
	Name: "plus",
	Decl: types.NewFunction(
		types.Args(types.N, types.N),
		types.N,
	),
	Family:      "numbers",
	Description: "``z`` is the sum of ``x`` and ``y``",
	Infix:       "+",
}

// Minus subtracts the second number from the first number or computes the diff
// between two sets.
var Minus = &Builtin{
	Name: "minus",
	Decl: types.NewFunction(
		types.Args(
			types.NewAny(types.N, types.NewSet(types.A)),
			types.NewAny(types.N, types.NewSet(types.A)),
		),
		types.NewAny(types.N, types.NewSet(types.A)),
	),
	Family:      "numbers",
	Description: "``z`` is the difference of ``x`` and ``y``",
	Infix:       "-",
}

// Multiply multiplies two numbers together.
var Multiply = &Builtin{
	Name: "mul",
	Decl: types.NewFunction(
		types.Args(types.N, types.N),
		types.N,
	),
	Family:      "numbers",
	Description: "``z`` is the product of ``x`` and ``y``",
	Infix:       "*",
}

// Divide divides the first number by the second number.
var Divide = &Builtin{
	Name: "div",
	Decl: types.NewFunction(
		types.Args(types.N, types.N),
		types.N,
	),
	Family:      "numbers",
	Description: "``z`` is the quotient of ``x`` and ``y``",
	Infix:       "/",
}

// Round rounds the number up to the nearest integer.
var Round = &Builtin{
	Name: "round",
	Decl: types.NewFunction(
		types.Args(types.N),
		types.N,
	),
	Family:      "numbers",
	Description: "``output`` is ``x`` rounded to the nearest integer",
}

// Abs returns the number without its sign.
var Abs = &Builtin{
	Name: "abs",
	Decl: types.NewFunction(
		types.Args(types.N),
		types.N,
	),
	Family:      "numbers",
	Description: "``output`` is the absolute value of ``x``",
}

// Rem returns the remainder for x%y for y != 0.
var Rem = &Builtin{
	Name: "rem",
	Decl: types.NewFunction(
		types.Args(types.N, types.N),
		types.N,
	),
	Family:      "numbers",
	Description: "``z`` is the remainder from the division of ``x`` and ``y``",
	Infix:       "%",
}

/**
 * Bitwise
 */

// BitsOr returns the bitwise "or" of two integers.
var BitsOr = &Builtin{
	Name: "bits.or",
	Decl: types.NewFunction(
		types.Args(types.N, types.N),
		types.N,
	),
}

// BitsAnd returns the bitwise "and" of two integers.
var BitsAnd = &Builtin{
	Name: "bits.and",
	Decl: types.NewFunction(
		types.Args(types.N, types.N),
		types.N,
	),
}

// BitsNegate returns the bitwise "negation" of an integer (i.e. flips each
// bit).
var BitsNegate = &Builtin{
	Name: "bits.negate",
	Decl: types.NewFunction(
		types.Args(types.N),
		types.N,
	),
}

// BitsXOr returns the bitwise "exclusive-or" of two integers.
var BitsXOr = &Builtin{
	Name: "bits.xor",
	Decl: types.NewFunction(
		types.Args(types.N, types.N),
		types.N,
	),
}

// BitsShiftLeft returns a new integer with its bits shifted some value to the
// left.
var BitsShiftLeft = &Builtin{
	Name: "bits.lsh",
	Decl: types.NewFunction(
		types.Args(types.N, types.N),
		types.N,
	),
}

// BitsShiftRight returns a new integer with its bits shifted some value to the
// right.
var BitsShiftRight = &Builtin{
	Name: "bits.rsh",
	Decl: types.NewFunction(
		types.Args(types.N, types.N),
		types.N,
	),
}

/**
 * Sets
 */

// And performs an intersection operation on sets.
var And = &Builtin{
	Name: "and",
	Decl: types.NewFunction(
		types.Args(
			types.NewSet(types.A),
			types.NewSet(types.A),
		),
		types.NewSet(types.A),
	),
	Family:      "sets",
	Description: "``z`` is the intersection of ``x`` and ``y``",
	Infix:       "&",
}

// Or performs a union operation on sets.
var Or = &Builtin{
	Name: "or",
	Decl: types.NewFunction(
		types.Args(
			types.NewSet(types.A),
			types.NewSet(types.A),
		),
		types.NewSet(types.A),
	),
	Family:      "sets",
	Description: "``z`` is the union of ``x`` and ``y``",
	Infix:       "|",
}

/**
 * Aggregates
 */

// Count takes a collection or string and counts the number of elements in it.
var Count = &Builtin{
	Name: "count",
	Decl: types.NewFunction(
		types.Args(
			types.NewAny(
				types.NewArray(nil, types.A),
				types.NewSet(types.A),
				types.NewObject(nil, types.NewDynamicProperty(types.A, types.A)),
				types.S,
			),
		),
		types.N,
	),
	Family:      "aggregates",
	Description: "``output`` is the length of the array, set, object or string provided as input",
}

// Sum takes an array or set of numbers and sums them.
var Sum = &Builtin{
	Name: "sum",
	Decl: types.NewFunction(
		types.Args(
			types.NewAny(
				types.NewArray(nil, types.N),
				types.NewSet(types.N),
			),
		),
		types.N,
	),
	Family:      "aggregates",
	Description: "``output`` is the sum of the numbers in ``array_or_set``",
}

// Product takes an array or set of numbers and multiplies them.
var Product = &Builtin{
	Name: "product",
	Decl: types.NewFunction(
		types.Args(
			types.NewAny(
				types.NewArray(nil, types.N),
				types.NewSet(types.N),
			),
		),
		types.N,
	),
	Family:      "aggregates",
	Description: "``output`` is the product of the numbers in ``array_or_set``",
}

// Max returns the maximum value in a collection.
var Max = &Builtin{
	Name: "max",
	Decl: types.NewFunction(
		types.Args(
			types.NewAny(
				types.NewArray(nil, types.A),
				types.NewSet(types.A),
			),
		),
		types.A,
	),
	Family:      "aggregates",
	Description: "``output`` is the maximum value in ``array_or_set``",
}

// Min returns the minimum value in a collection.
var Min = &Builtin{
	Name: "min",
	Decl: types.NewFunction(
		types.Args(
			types.NewAny(
				types.NewArray(nil, types.A),
				types.NewSet(types.A),
			),
		),
		types.A,
	),
	Family:      "aggregates",
	Description: "``output`` is the minimum value in ``array_or_set``",
}

// All takes a list and returns true if all of the items
// are true. A collection of length 0 returns true.
var All = &Builtin{
	Name: "all",
	Decl: types.NewFunction(
		types.Args(
			types.NewAny(
				types.NewArray(nil, types.A),
				types.NewSet(types.A),
			),
		),
		types.B,
	),
	Family:      "aggregates",
	Description: "``output`` is ``true`` if all of the values in ``array_or_set`` are ``true``. A collection of length 0 returns ``true``",
}

// Any takes a collection and returns true if any of the items
// is true. A collection of length 0 returns false.
var Any = &Builtin{
	Name: "any",
	Decl: types.NewFunction(
		types.Args(
			types.NewAny(
				types.NewArray(nil, types.A),
				types.NewSet(types.A),
			),
		),
		types.B,
	),
	Family:      "aggregates",
	Description: "``output`` is ``true`` if any of the values in ``array_or_set`` is ``true``. A collection of length 0 returns ``false``",
}

/**
 * Arrays
 */

// ArrayConcat returns the result of concatenating two arrays together.
var ArrayConcat = &Builtin{
	Name: "array.concat",
	Decl: types.NewFunction(
		types.Args(
			types.NewArray(nil, types.A),
			types.NewArray(nil, types.A),
		),
		types.NewArray(nil, types.A),
	),
	Family:      "arrays",
	Description: "``output`` is the result of concatenating the two input arrays together",
}

// ArraySlice returns a slice of a given array
var ArraySlice = &Builtin{
	Name: "array.slice",
	Decl: types.NewFunction(
		types.Args(
			types.NewArray(nil, types.A),
			types.NewNumber(),
			types.NewNumber(),
		),
		types.NewArray(nil, types.A),
	),
	Family:      "arrays",
	Description: "``output`` is the part of the ``array`` starting from index ``x`` to ``y`` including the first index but excluding the last. If `x >= y` then `output == []`. If both `x` and `y` are less than zero, `output == []`. Otherwise, `x` and `y` are clamped to 0 and `count(array)` respectively",
}

/**
 * Conversions
 */

// ToNumber takes a string, bool, or number value and converts it to a number.
// Strings are converted to numbers using strconv.Atoi.
// Boolean false is converted to 0 and boolean true is converted to 1.
var ToNumber = &Builtin{
	Name: "to_number",
	Decl: types.NewFunction(
		types.Args(
			types.NewAny(
				types.N,
				types.S,
				types.B,
				types.NewNull(),
			),
		),
		types.N,
	),
}

/**
 * Regular Expressions
 */

// RegexMatch takes two strings and evaluates to true if the string in the second
// position matches the pattern in the first position.
var RegexMatch = &Builtin{
	Name: "regex.match",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// RegexIsValid returns true if the regex pattern string is valid, otherwise false.
var RegexIsValid = &Builtin{
	Name: "regex.is_valid",
	Decl: types.NewFunction(
		types.Args(
			types.S,
		),
		types.B,
	),
}

// RegexFindAllStringSubmatch returns an array of all successive matches of the expression.
// It takes two strings and a number, the pattern, the value and number of matches to
// return, -1 means all matches.
var RegexFindAllStringSubmatch = &Builtin{
	Name: "regex.find_all_string_submatch_n",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
			types.N,
		),
		types.NewArray(nil, types.NewArray(nil, types.S)),
	),
}

// RegexTemplateMatch takes two strings and evaluates to true if the string in the second
// position matches the pattern in the first position.
var RegexTemplateMatch = &Builtin{
	Name: "regex.template_match",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
			types.S,
			types.S,
		),
		types.B,
	),
}

// RegexSplit splits the input string by the occurrences of the given pattern.
var RegexSplit = &Builtin{
	Name: "regex.split",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.NewArray(nil, types.S),
	),
}

// RegexFind takes two strings and a number, the pattern, the value and number of match values to
// return, -1 means all match values.
var RegexFind = &Builtin{
	Name: "regex.find_n",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
			types.N,
		),
		types.NewArray(nil, types.S),
	),
}

// GlobsMatch takes two strings regexp-style strings and evaluates to true if their
// intersection matches a non-empty set of non-empty strings.
// Examples:
//  - "a.a." and ".b.b" -> true.
//  - "[a-z]*" and [0-9]+" -> not true.
var GlobsMatch = &Builtin{
	Name: "regex.globs_match",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

/**
 * Strings
 */

// Concat joins an array of strings with an input string.
var Concat = &Builtin{
	Name: "concat",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.NewAny(
				types.NewArray(nil, types.S),
				types.NewSet(types.S),
			),
		),
		types.S,
	),
	Family:      "strings",
	Description: "`output` is the result of joining together the elements of `array_or_set` with the delimiter specified by string `x`",
}

// FormatInt returns the string representation of the number in the given base after converting it to an integer value.
var FormatInt = &Builtin{
	Name: "format_int",
	Decl: types.NewFunction(
		types.Args(
			types.N,
			types.N,
		),
		types.S,
	),
	Family:      "strings",
	Description: "`output` is string representation of number `x` in the given base `y`",
}

// IndexOf returns the index of a substring contained inside a string
var IndexOf = &Builtin{
	Name: "indexof",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.N,
	),
	Family:      "strings",
	Description: "`output` is the index inside string `x` where `y` first occurs, or -1 if `y` does not exist",
}

// Substring returns the portion of a string for a given start index and a length.
//   If the length is less than zero, then substring returns the remainder of the string.
var Substring = &Builtin{
	Name: "substring",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.N,
			types.N,
		),
		types.S,
	),
	Family:      "strings",
	Description: "`output` is the portion of string `x` from index `y` and having a length of `z`. If `z` is less than zero, `z` is the remainder of the string. If index `y` is greater than the length of the string, `output` is empty. It is invalid to pass a negative offset to this function.",
}

// Contains returns true if the search string is included in the base string
var Contains = &Builtin{
	Name: "contains",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
	Family:      "strings",
	Description: "true if string `x` contains `y`",
}

// StartsWith returns true if the search string begins with the base string
var StartsWith = &Builtin{
	Name: "startswith",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
	Family:      "strings",
	Description: "true if string `x` begins with `y`",
}

// EndsWith returns true if the search string begins with the base string
var EndsWith = &Builtin{
	Name: "endswith",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
	Family:      "strings",
	Description: "true if string `x` ends with `y`",
}

// Lower returns the input string but with all characters in lower-case
var Lower = &Builtin{
	Name: "lower",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.S,
	),
	Family:      "strings",
	Description: "`output` is string `x` after converting to lower case",
}

// Upper returns the input string but with all characters in upper-case
var Upper = &Builtin{
	Name: "upper",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.S,
	),
	Family:      "strings",
	Description: "`output` is string `x` after converting to upper case",
}

// Split returns an array containing elements of the input string split on a delimiter.
var Split = &Builtin{
	Name: "split",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.NewArray(nil, types.S),
	),
	Family:      "strings",
	Description: "`output` is `array[string]` representing elements of string `x` separated by delimiter `y`",
}

// Replace returns the given string with all instances of the second argument replaced
// by the third.
var Replace = &Builtin{
	Name: "replace",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
			types.S,
		),
		types.S,
	),
	Family:      "strings",
	Description: "`output` is a `string` representing string `x` with all instances of `y` replaced by `z`",
}

// ReplaceN replaces a string from a list of old, new string pairs.
// Replacements are performed in the order they appear in the target string, without overlapping matches.
// The old string comparisons are done in argument order.
var ReplaceN = &Builtin{
	Name: "strings.replace_n",
	Decl: types.NewFunction(
		types.Args(
			types.NewObject(
				nil,
				types.NewDynamicProperty(
					types.S,
					types.S)),
			types.S,
		),
		types.S,
	),
	Family:      "strings",
	Description: "`object` is an object with old, new string key value pairs (e.g. {\"old1\": \"new1\", \"old2\": \"new2\", ...}). `output` is a `string` with all old strings inside `object` replaced by the new strings",
}

// Trim returns the given string with all leading or trailing instances of the second
// argument removed.
var Trim = &Builtin{
	Name: "trim",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.S,
	),
	Family:      "strings",
	Description: "`output` is a string representing string `x` with all leading and trailing instances of the characters in `y` removed",
}

// TrimLeft returns the given string with all leading instances of second argument removed.
var TrimLeft = &Builtin{
	Name: "trim_left",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.S,
	),
	Family:      "strings",
	Description: "`output` is a string representing string `x` with all leading instances of the characters in `y` removed",
}

// TrimPrefix returns the given string without the second argument prefix string.
// If the given string doesn't start with prefix, it is returned unchanged.
var TrimPrefix = &Builtin{
	Name: "trim_prefix",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.S,
	),
	Family:      "strings",
	Description: "`output` is a `string` representing string `x` with leading instance of prefix `y` removed. If `x` doesn't start with `y`, `x` is returned unchanged",
}

// TrimRight returns the given string with all trailing instances of second argument removed.
var TrimRight = &Builtin{
	Name: "trim_right",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.S,
	),
	Family:      "strings",
	Description: "`output` is a string representing string `x` with all trailing instances of the characters in `y` removed",
}

// TrimSuffix returns the given string without the second argument suffix string.
// If the given string doesn't end with suffix, it is returned unchanged.
var TrimSuffix = &Builtin{
	Name: "trim_suffix",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.S,
	),
	Family:      "strings",
	Description: "`output` is a `string` representing string `x` with trailing instance of suffix `y` removed. If `x` doesn't end with `y`, `x` is returned unchanged",
}

// TrimSpace return the given string with all leading and trailing white space removed.
var TrimSpace = &Builtin{
	Name: "trim_space",
	Decl: types.NewFunction(
		types.Args(
			types.S,
		),
		types.S,
	),
	Family:      "strings",
	Description: "`output` is a `string` representing string `x` with all leading and trailing white space removed",
}

// Sprintf returns the given string, formatted.
var Sprintf = &Builtin{
	Name: "sprintf",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.NewArray(nil, types.A),
		),
		types.S,
	),
	Family:      "strings",
	Description: "`output` is a string representing string `x` formatted by the values in `array`",
}

/**
 * Numbers
 */

// NumbersRange returns an array of numbers in the given inclusive range.
var NumbersRange = &Builtin{
	Name: "numbers.range",
	Decl: types.NewFunction(
		types.Args(
			types.N,
			types.N,
		),
		types.NewArray(nil, types.N),
	),
	Family:      "numbers",
	Description: "``output`` is the range of integer numbers between ``x`` and ``y`` (inclusive). If ``x`` == ``y`` then ``output`` == ``[x]``. If ``x`` < ``y`` the range is in ascending order. If ``x`` > ``y`` the range is in descending order.",
}

/**
 * Units
 */

// UnitsParseBytes converts strings like 10GB, 5K, 4mb, and the like into an
// integer number of bytes.
var UnitsParseBytes = &Builtin{
	Name: "units.parse_bytes",
	Decl: types.NewFunction(
		types.Args(
			types.S,
		),
		types.N,
	),
}

//
/**
 * Type
 */

// UUIDRFC4122 returns a version 4 UUID string.
var UUIDRFC4122 = &Builtin{
	Name: "uuid.rfc4122",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.S,
	),
}

/**
 * JSON
 */

// JSONMarshal serializes the input term.
var JSONMarshal = &Builtin{
	Name: "json.marshal",
	Decl: types.NewFunction(
		types.Args(types.A),
		types.S,
	),
}

// JSONUnmarshal deserializes the input string.
var JSONUnmarshal = &Builtin{
	Name: "json.unmarshal",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.A,
	),
}

// JSONIsValid verifies the input string is a valid JSON document.
var JSONIsValid = &Builtin{
	Name: "json.is_valid",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.B,
	),
}

// JSONFilter filters the JSON object
var JSONFilter = &Builtin{
	Name: "json.filter",
	Decl: types.NewFunction(
		types.Args(
			types.NewObject(
				nil,
				types.NewDynamicProperty(types.A, types.A),
			),
			types.NewAny(
				types.NewArray(
					nil,
					types.NewAny(
						types.S,
						types.NewArray(
							nil,
							types.A,
						),
					),
				),
				types.NewSet(
					types.NewAny(
						types.S,
						types.NewArray(
							nil,
							types.A,
						),
					),
				),
			),
		),
		types.A,
	),
	Family:      "objects",
	Description: "`output` is the remaining data from `object` with only keys specified in `array_or_set` which is an array or set of JSON string paths. For example: `json.filter({\"a\": {\"b\": \"x\", \"c\": \"y\"}}, [\"a/b\"])` will result in `{\"a\": {\"b\": \"x\"}}`). Paths are not filtered in-order and are deduplicated before being evaluated",
}

// JSONRemove removes paths in the JSON object
var JSONRemove = &Builtin{
	Name: "json.remove",
	Decl: types.NewFunction(
		types.Args(
			types.NewObject(
				nil,
				types.NewDynamicProperty(types.A, types.A),
			),
			types.NewAny(
				types.NewArray(
					nil,
					types.NewAny(
						types.S,
						types.NewArray(
							nil,
							types.A,
						),
					),
				),
				types.NewSet(
					types.NewAny(
						types.S,
						types.NewArray(
							nil,
							types.A,
						),
					),
				),
			),
		),
		types.A,
	),
	Family:      "objects",
	Description: "`output` is a new object which is the result of removing all keys specified in `array_or_set` which is an array or set of JSON string paths. For example: `json.remove({\"a\": {\"b\": \"x\", \"c\": \"y\"}}, [\"a/b\"])` will result in `{\"a\": {\"c\": \"y\"}}`. Paths are not removed in-order and are deduplicated before being evaluated",
}

// ObjectGet returns takes an object and returns a value under its key if
// present, otherwise it returns the default.
var ObjectGet = &Builtin{
	Name: "object.get",
	Decl: types.NewFunction(
		types.Args(
			types.NewObject(nil, types.NewDynamicProperty(types.A, types.A)),
			types.A,
			types.A,
		),
		types.A,
	),
	Family:      "objects",
	Description: "`output` is the value stored by the `object` at key `x`. If no value is found, the default value `y` is returned",
}

// ObjectUnion creates a new object that is the asymmetric union of two objects
var ObjectUnion = &Builtin{
	Name: "object.union",
	Decl: types.NewFunction(
		types.Args(
			types.NewObject(
				nil,
				types.NewDynamicProperty(types.A, types.A),
			),
			types.NewObject(
				nil,
				types.NewDynamicProperty(types.A, types.A),
			),
		),
		types.A,
	),
	Family:      "objects",
	Description: "`output` is a new object which is the result of an asymmetric recursive union of two objects where conflicts are resolved by choosing the key from the right-hand object. For example: `object.union({\"a\": 1, \"b\": 2, \"c\": {\"d\": 3}}, {\"a\": 7, \"c\": {\"d\": 4, \"e\": 5}})` will result in `{\"a\": 7, \"b\": 2, \"c\": {\"d\": 4, \"e\": 5}}`",
}

// ObjectRemove Removes specified keys from an object
var ObjectRemove = &Builtin{
	Name: "object.remove",
	Decl: types.NewFunction(
		types.Args(
			types.NewObject(
				nil,
				types.NewDynamicProperty(types.A, types.A),
			),
			types.NewAny(
				types.NewArray(nil, types.A),
				types.NewSet(types.A),
				types.NewObject(nil, types.NewDynamicProperty(types.A, types.A)),
			),
		),
		types.A,
	),
	Family:      "objects",
	Description: "`output` is a new object which is the result of removing the keys specified in `array_or_set_or_object` from `object`. The keys must be either an array, set, or object of keys",
}

// ObjectFilter filters the object by keeping only specified keys
var ObjectFilter = &Builtin{
	Name: "object.filter",
	Decl: types.NewFunction(
		types.Args(
			types.NewObject(
				nil,
				types.NewDynamicProperty(types.A, types.A),
			),
			types.NewAny(
				types.NewArray(nil, types.A),
				types.NewSet(types.A),
				types.NewObject(nil, types.NewDynamicProperty(types.A, types.A)),
			),
		),
		types.A,
	),
	Family:      "objects",
	Description: "`output` is a new object with the remaining data from `object` with only keys specified in `array_or_set_or_object` which is an array, set, or object of keys. For example: `object.filter({\"a\": {\"b\": \"x\", \"c\": \"y\"}, \"d\": \"z\"}, [\"a\"])` will result in `{\"a\": {\"b\": \"x\", \"c\": \"y\"}}`)",
}

// Base64Encode serializes the input string into base64 encoding.
var Base64Encode = &Builtin{
	Name: "base64.encode",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.S,
	),
}

// Base64Decode deserializes the base64 encoded input string.
var Base64Decode = &Builtin{
	Name: "base64.decode",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.S,
	),
}

// Base64IsValid verifies the input string is base64 encoded.
var Base64IsValid = &Builtin{
	Name: "base64.is_valid",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.B,
	),
}

// Base64UrlEncode serializes the input string into base64url encoding.
var Base64UrlEncode = &Builtin{
	Name: "base64url.encode",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.S,
	),
}

// Base64UrlEncodeNoPad serializes the input string into base64url encoding without padding.
var Base64UrlEncodeNoPad = &Builtin{
	Name: "base64url.encode_no_pad",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.S,
	),
}

// Base64UrlDecode deserializes the base64url encoded input string.
var Base64UrlDecode = &Builtin{
	Name: "base64url.decode",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.S,
	),
}

// URLQueryDecode decodes a URL encoded input string.
var URLQueryDecode = &Builtin{
	Name: "urlquery.decode",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.S,
	),
}

// URLQueryEncode encodes the input string into a URL encoded string.
var URLQueryEncode = &Builtin{
	Name: "urlquery.encode",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.S,
	),
}

// URLQueryEncodeObject encodes the given JSON into a URL encoded query string.
var URLQueryEncodeObject = &Builtin{
	Name: "urlquery.encode_object",
	Decl: types.NewFunction(
		types.Args(
			types.NewObject(
				nil,
				types.NewDynamicProperty(
					types.S,
					types.NewAny(
						types.S,
						types.NewArray(nil, types.S),
						types.NewSet(types.S))))),
		types.S,
	),
}

// URLQueryDecodeObject decodes the given URL query string into an object.
var URLQueryDecodeObject = &Builtin{
	Name: "urlquery.decode_object",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.NewObject(nil, types.NewDynamicProperty(
			types.S,
			types.NewArray(nil, types.S))),
	),
}

// YAMLMarshal serializes the input term.
var YAMLMarshal = &Builtin{
	Name: "yaml.marshal",
	Decl: types.NewFunction(
		types.Args(types.A),
		types.S,
	),
}

// YAMLUnmarshal deserializes the input string.
var YAMLUnmarshal = &Builtin{
	Name: "yaml.unmarshal",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.A,
	),
}

// YAMLIsValid verifies the input string is a valid YAML document.
var YAMLIsValid = &Builtin{
	Name: "yaml.is_valid",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.B,
	),
}

// HexEncode serializes the input string into hex encoding.
var HexEncode = &Builtin{
	Name: "hex.encode",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.S,
	),
}

// HexDecode deserializes the hex encoded input string.
var HexDecode = &Builtin{
	Name: "hex.decode",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.S,
	),
}

/**
 * Tokens
 */

// JWTDecode decodes a JSON Web Token and outputs it as an Object.
var JWTDecode = &Builtin{
	Name: "io.jwt.decode",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.NewArray([]types.Type{
			types.NewObject(nil, types.NewDynamicProperty(types.A, types.A)),
			types.NewObject(nil, types.NewDynamicProperty(types.A, types.A)),
			types.S,
		}, nil),
	),
}

// JWTVerifyRS256 verifies if a RS256 JWT signature is valid or not.
var JWTVerifyRS256 = &Builtin{
	Name: "io.jwt.verify_rs256",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// JWTVerifyRS384 verifies if a RS384 JWT signature is valid or not.
var JWTVerifyRS384 = &Builtin{
	Name: "io.jwt.verify_rs384",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// JWTVerifyRS512 verifies if a RS512 JWT signature is valid or not.
var JWTVerifyRS512 = &Builtin{
	Name: "io.jwt.verify_rs512",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// JWTVerifyPS256 verifies if a PS256 JWT signature is valid or not.
var JWTVerifyPS256 = &Builtin{
	Name: "io.jwt.verify_ps256",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// JWTVerifyPS384 verifies if a PS384 JWT signature is valid or not.
var JWTVerifyPS384 = &Builtin{
	Name: "io.jwt.verify_ps384",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// JWTVerifyPS512 verifies if a PS512 JWT signature is valid or not.
var JWTVerifyPS512 = &Builtin{
	Name: "io.jwt.verify_ps512",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// JWTVerifyES256 verifies if a ES256 JWT signature is valid or not.
var JWTVerifyES256 = &Builtin{
	Name: "io.jwt.verify_es256",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// JWTVerifyES384 verifies if a ES384 JWT signature is valid or not.
var JWTVerifyES384 = &Builtin{
	Name: "io.jwt.verify_es384",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// JWTVerifyES512 verifies if a ES512 JWT signature is valid or not.
var JWTVerifyES512 = &Builtin{
	Name: "io.jwt.verify_es512",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// JWTVerifyHS256 verifies if a HS256 (secret) JWT signature is valid or not.
var JWTVerifyHS256 = &Builtin{
	Name: "io.jwt.verify_hs256",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// JWTVerifyHS384 verifies if a HS384 (secret) JWT signature is valid or not.
var JWTVerifyHS384 = &Builtin{
	Name: "io.jwt.verify_hs384",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// JWTVerifyHS512 verifies if a HS512 (secret) JWT signature is valid or not.
var JWTVerifyHS512 = &Builtin{
	Name: "io.jwt.verify_hs512",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// JWTDecodeVerify verifies a JWT signature under parameterized constraints and decodes the claims if it is valid.
var JWTDecodeVerify = &Builtin{
	Name: "io.jwt.decode_verify",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)),
		),
		types.NewArray([]types.Type{
			types.B,
			types.NewObject(nil, types.NewDynamicProperty(types.A, types.A)),
			types.NewObject(nil, types.NewDynamicProperty(types.A, types.A)),
		}, nil),
	),
}

// JWTEncodeSignRaw encodes and optionally sign  a JSON Web Token.
// Inputs are protected headers, payload, secret
var JWTEncodeSignRaw = &Builtin{
	Name: "io.jwt.encode_sign_raw",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
			types.S,
		),
		types.S,
	),
}

// JWTEncodeSign encodes and optionally sign  a JSON Web Token.
// Inputs are protected headers, payload, secret
var JWTEncodeSign = &Builtin{
	Name: "io.jwt.encode_sign",
	Decl: types.NewFunction(
		types.Args(
			types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)),
			types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)),
			types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)),
		),
		types.S,
	),
}

/**
 * Time
 */

// NowNanos returns the current time since epoch in nanoseconds.
var NowNanos = &Builtin{
	Name: "time.now_ns",
	Decl: types.NewFunction(
		nil,
		types.N,
	),
}

// ParseNanos returns the time in nanoseconds parsed from the string in the given format.
var ParseNanos = &Builtin{
	Name: "time.parse_ns",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.N,
	),
}

// ParseRFC3339Nanos returns the time in nanoseconds parsed from the string in RFC3339 format.
var ParseRFC3339Nanos = &Builtin{
	Name: "time.parse_rfc3339_ns",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.N,
	),
}

// ParseDurationNanos returns the duration in nanoseconds represented by a duration string.
// Duration string is similar to the Go time.ParseDuration string
var ParseDurationNanos = &Builtin{
	Name: "time.parse_duration_ns",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.N,
	),
}

// Date returns the [year, month, day] for the nanoseconds since epoch.
var Date = &Builtin{
	Name: "time.date",
	Decl: types.NewFunction(
		types.Args(
			types.NewAny(
				types.N,
				types.NewArray([]types.Type{types.N, types.S}, nil),
			),
		),
		types.NewArray([]types.Type{types.N, types.N, types.N}, nil),
	),
}

// Clock returns the [hour, minute, second] of the day for the nanoseconds since epoch.
var Clock = &Builtin{
	Name: "time.clock",
	Decl: types.NewFunction(
		types.Args(
			types.NewAny(
				types.N,
				types.NewArray([]types.Type{types.N, types.S}, nil),
			),
		),
		types.NewArray([]types.Type{types.N, types.N, types.N}, nil),
	),
}

// Weekday returns the day of the week (Monday, Tuesday, ...) for the nanoseconds since epoch.
var Weekday = &Builtin{
	Name: "time.weekday",
	Decl: types.NewFunction(
		types.Args(
			types.NewAny(
				types.N,
				types.NewArray([]types.Type{types.N, types.S}, nil),
			),
		),
		types.S,
	),
}

// AddDate returns the nanoseconds since epoch after adding years, months and days to nanoseconds.
var AddDate = &Builtin{
	Name: "time.add_date",
	Decl: types.NewFunction(
		types.Args(
			types.N,
			types.N,
			types.N,
			types.N,
		),
		types.N,
	),
}

/**
 * Crypto.
 */

// CryptoX509ParseCertificates returns one or more certificates from the given
// base64 encoded string containing DER encoded certificates that have been
// concatenated.
var CryptoX509ParseCertificates = &Builtin{
	Name: "crypto.x509.parse_certificates",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.NewArray(nil, types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))),
	),
}

// CryptoX509ParseCertificateRequest returns a PKCS #10 certificate signing
// request from the given PEM-encoded PKCS#10 certificate signing request.
var CryptoX509ParseCertificateRequest = &Builtin{
	Name: "crypto.x509.parse_certificate_request",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)),
	),
}

// CryptoMd5 returns a string representing the input string hashed with the md5 function
var CryptoMd5 = &Builtin{
	Name: "crypto.md5",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.S,
	),
}

// CryptoSha1 returns a string representing the input string hashed with the sha1 function
var CryptoSha1 = &Builtin{
	Name: "crypto.sha1",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.S,
	),
}

// CryptoSha256 returns a string representing the input string hashed with the sha256 function
var CryptoSha256 = &Builtin{
	Name: "crypto.sha256",
	Decl: types.NewFunction(
		types.Args(types.S),
		types.S,
	),
}

/**
 * Graphs.
 */

// WalkBuiltin generates [path, value] tuples for all nested documents
// (recursively).
var WalkBuiltin = &Builtin{
	Name:     "walk",
	Relation: true,
	Decl: types.NewFunction(
		types.Args(types.A),
		types.NewArray(
			[]types.Type{
				types.NewArray(nil, types.A),
				types.A,
			},
			nil,
		),
	),
}

// ReachableBuiltin computes the set of reachable nodes in the graph from a set
// of starting nodes.
var ReachableBuiltin = &Builtin{
	Name: "graph.reachable",
	Decl: types.NewFunction(
		types.Args(
			types.NewObject(
				nil,
				types.NewDynamicProperty(
					types.A,
					types.NewAny(
						types.NewSet(types.A),
						types.NewArray(nil, types.A)),
				)),
			types.NewAny(types.NewSet(types.A), types.NewArray(nil, types.A)),
		),
		types.NewSet(types.A),
	),
}

/**
 * Sorting
 */

// Sort returns a sorted array.
var Sort = &Builtin{
	Name: "sort",
	Decl: types.NewFunction(
		types.Args(
			types.NewAny(
				types.NewArray(nil, types.A),
				types.NewSet(types.A),
			),
		),
		types.NewArray(nil, types.A),
	),
	Family:      "aggregates",
	Description: "``output`` is the sorted ``array`` containing elements from ``array_or_set``",
}

/**
 * Type
 */

// IsNumber returns true if the input value is a number
var IsNumber = &Builtin{
	Name: "is_number",
	Decl: types.NewFunction(
		types.Args(
			types.A,
		),
		types.B,
	),
}

// IsString returns true if the input value is a string.
var IsString = &Builtin{
	Name: "is_string",
	Decl: types.NewFunction(
		types.Args(
			types.A,
		),
		types.B,
	),
}

// IsBoolean returns true if the input value is a boolean.
var IsBoolean = &Builtin{
	Name: "is_boolean",
	Decl: types.NewFunction(
		types.Args(
			types.A,
		),
		types.B,
	),
}

// IsArray returns true if the input value is an array.
var IsArray = &Builtin{
	Name: "is_array",
	Decl: types.NewFunction(
		types.Args(
			types.A,
		),
		types.B,
	),
}

// IsSet returns true if the input value is a set.
var IsSet = &Builtin{
	Name: "is_set",
	Decl: types.NewFunction(
		types.Args(
			types.A,
		),
		types.B,
	),
}

// IsObject returns true if the input value is an object.
var IsObject = &Builtin{
	Name: "is_object",
	Decl: types.NewFunction(
		types.Args(
			types.A,
		),
		types.B,
	),
}

// IsNull returns true if the input value is null.
var IsNull = &Builtin{
	Name: "is_null",
	Decl: types.NewFunction(
		types.Args(
			types.A,
		),
		types.B,
	),
}

/**
 * Type Name
 */

// TypeNameBuiltin returns the type of the input.
var TypeNameBuiltin = &Builtin{
	Name: "type_name",
	Decl: types.NewFunction(
		types.Args(
			types.NewAny(
				types.A,
			),
		),
		types.S,
	),
}

/**
 * HTTP Request
 */

// HTTPSend returns a HTTP response to the given HTTP request.
var HTTPSend = &Builtin{
	Name: "http.send",
	Decl: types.NewFunction(
		types.Args(
			types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)),
		),
		types.NewObject(nil, types.NewDynamicProperty(types.A, types.A)),
	),
}

/**
 * Rego
 */

// RegoParseModule parses the input Rego file and returns a JSON representation
// of the AST.
var RegoParseModule = &Builtin{
	Name: "rego.parse_module",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)), // TODO(tsandall): import AST schema
	),
}

/**
 * OPA
 */

// OPARuntime returns an object containing OPA runtime information such as the
// configuration that OPA was booted with.
var OPARuntime = &Builtin{
	Name: "opa.runtime",
	Decl: types.NewFunction(
		nil,
		types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)),
	),
}

/**
 * Trace
 */

// Trace prints a note that is included in the query explanation.
var Trace = &Builtin{
	Name: "trace",
	Decl: types.NewFunction(
		types.Args(
			types.S,
		),
		types.B,
	),
}

/**
 * Set
 */

// Intersection returns the intersection of the given input sets
var Intersection = &Builtin{
	Name: "intersection",
	Decl: types.NewFunction(
		types.Args(
			types.NewSet(types.NewSet(types.A)),
		),
		types.NewSet(types.A),
	),
	Family:      "sets",
	Description: "``output`` is the intersection of the sets in the input set",
}

// Union returns the union of the given input sets
var Union = &Builtin{
	Name: "union",
	Decl: types.NewFunction(
		types.Args(
			types.NewSet(types.NewSet(types.A)),
		),
		types.NewSet(types.A),
	),
	Family:      "sets",
	Description: "``output`` is the union of the sets in the input set",
}

/**
 * Glob
 */

// GlobMatch - not to be confused with regex.globs_match - parses and matches strings against the glob notation.
var GlobMatch = &Builtin{
	Name: "glob.match",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.NewArray(nil, types.S),
			types.S,
		),
		types.B,
	),
}

// GlobQuoteMeta returns a string which represents a version of the pattern where all asterisks have been escaped.
var GlobQuoteMeta = &Builtin{
	Name: "glob.quote_meta",
	Decl: types.NewFunction(
		types.Args(
			types.S,
		),
		types.S,
	),
}

/**
 * Net CIDR
 */

// NetCIDRIntersects checks if a cidr intersects with another cidr and returns true or false
var NetCIDRIntersects = &Builtin{
	Name: "net.cidr_intersects",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// NetCIDRExpand returns a set of hosts inside the specified cidr.
var NetCIDRExpand = &Builtin{
	Name: "net.cidr_expand",
	Decl: types.NewFunction(
		types.Args(
			types.S,
		),
		types.NewSet(types.S),
	),
}

// NetCIDRContains checks if a cidr or ip is contained within another cidr and returns true or false
var NetCIDRContains = &Builtin{
	Name: "net.cidr_contains",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// NetCIDRContainsMatches checks if collections of cidrs or ips are contained within another collection of cidrs and returns matches.
var NetCIDRContainsMatches = &Builtin{
	Name: "net.cidr_contains_matches",
	Decl: types.NewFunction(
		types.Args(netCidrContainsMatchesOperandType, netCidrContainsMatchesOperandType),
		types.NewSet(types.NewArray([]types.Type{types.A, types.A}, nil)),
	),
}

// NetCIDRMerge merges IP addresses and subnets into the smallest possible list of CIDRs.
var NetCIDRMerge = &Builtin{
	Name: "net.cidr_merge",
	Decl: types.NewFunction(
		types.Args(netCidrMergeOperandType),
		types.NewSet(types.S),
	),
}

var netCidrMergeOperandType = types.NewAny(
	types.NewArray(nil, types.NewAny(types.S)),
	types.NewSet(types.S),
)

var netCidrContainsMatchesOperandType = types.NewAny(
	types.S,
	types.NewArray(nil, types.NewAny(
		types.S,
		types.NewArray(nil, types.A),
	)),
	types.NewSet(types.NewAny(
		types.S,
		types.NewArray(nil, types.A),
	)),
	types.NewObject(nil, types.NewDynamicProperty(
		types.S,
		types.NewAny(
			types.S,
			types.NewArray(nil, types.A),
		),
	)),
)

/**
 * Semantic Versions
 */

// SemVerIsValid validiates a the term is a valid SemVer as a string, returns
// false for all other input
var SemVerIsValid = &Builtin{
	Name: "semver.is_valid",
	Decl: types.NewFunction(
		types.Args(
			types.A,
		),
		types.B,
	),
}

// SemVerCompare compares valid SemVer formatted version strings. Given two
// version strings, if A < B returns -1, if A > B returns 1. If A == B, returns
// 0
var SemVerCompare = &Builtin{
	Name: "semver.compare",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.N,
	),
}

/**
 * Deprecated built-ins.
 */

// SetDiff has been replaced by the minus built-in.
var SetDiff = &Builtin{
	Name: "set_diff",
	Decl: types.NewFunction(
		types.Args(
			types.NewSet(types.A),
			types.NewSet(types.A),
		),
		types.NewSet(types.A),
	),
	Family:      "sets",
	Description: "``z`` is the difference between ``x`` and ``y``, i.e., the elements in ``x`` that are not in ``y``",
	Infix:       "-",
}

// NetCIDROverlap has been replaced by the `net.cidr_contains` built-in.
var NetCIDROverlap = &Builtin{
	Name: "net.cidr_overlap",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// CastArray checks the underlying type of the input. If it is array or set, an array
// containing the values is returned. If it is not an array, an error is thrown.
var CastArray = &Builtin{
	Name: "cast_array",
	Decl: types.NewFunction(
		types.Args(types.A),
		types.NewArray(nil, types.A),
	),
}

// CastSet checks the underlying type of the input.
// If it is a set, the set is returned.
// If it is an array, the array is returned in set form (all duplicates removed)
// If neither, an error is thrown
var CastSet = &Builtin{
	Name: "cast_set",
	Decl: types.NewFunction(
		types.Args(types.A),
		types.NewSet(types.A),
	),
}

// CastString returns input if it is a string; if not returns error.
// For formatting variables, see sprintf
var CastString = &Builtin{
	Name: "cast_string",
	Decl: types.NewFunction(
		types.Args(types.A),
		types.S,
	),
}

// CastBoolean returns input if it is a boolean; if not returns error.
var CastBoolean = &Builtin{
	Name: "cast_boolean",
	Decl: types.NewFunction(
		types.Args(types.A),
		types.B,
	),
}

// CastNull returns null if input is null; if not returns error.
var CastNull = &Builtin{
	Name: "cast_null",
	Decl: types.NewFunction(
		types.Args(types.A),
		types.NewNull(),
	),
}

// CastObject returns the given object if it is null; throws an error otherwise
var CastObject = &Builtin{
	Name: "cast_object",
	Decl: types.NewFunction(
		types.Args(types.A),
		types.NewObject(nil, types.NewDynamicProperty(types.A, types.A)),
	),
}

// RegexMatchDeprecated declares `re_match` which has been deprecated. Use `regex.match` instead.
var RegexMatchDeprecated = &Builtin{
	Name: "re_match",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.S,
		),
		types.B,
	),
}

// Builtin represents a built-in function supported by OPA. Every built-in
// function is uniquely identified by a name.
type Builtin struct {
	Name        string          `json:"name"`               // Unique name of built-in function, e.g., <name>(arg1,arg2,...,argN)
	Decl        *types.Function `json:"decl"`               // Built-in function type declaration.
	Family      string          `json:"family"`             // Indicates the family to which the built-in function belongs.
	Description string          `json:"description"`        // Built-in function description.
	Infix       string          `json:"infix,omitempty"`    // Unique name of infix operator. Default should be unset.
	Relation    bool            `json:"relation,omitempty"` // Indicates if the built-in acts as a relation.
}

// Expr creates a new expression for the built-in with the given operands.
func (b *Builtin) Expr(operands ...*Term) *Expr {
	ts := make([]*Term, len(operands)+1)
	ts[0] = NewTerm(b.Ref())
	for i := range operands {
		ts[i+1] = operands[i]
	}
	return &Expr{
		Terms: ts,
	}
}

// Call creates a new term for the built-in with the given operands.
func (b *Builtin) Call(operands ...*Term) *Term {
	call := make(Call, len(operands)+1)
	call[0] = NewTerm(b.Ref())
	for i := range operands {
		call[i+1] = operands[i]
	}
	return NewTerm(call)
}

// Ref returns a Ref that refers to the built-in function.
func (b *Builtin) Ref() Ref {
	parts := strings.Split(b.Name, ".")
	ref := make(Ref, len(parts))
	ref[0] = VarTerm(parts[0])
	for i := 1; i < len(parts); i++ {
		ref[i] = StringTerm(parts[i])
	}
	return ref
}

// IsTargetPos returns true if a variable in the i-th position will be bound by
// evaluating the call expression.
func (b *Builtin) IsTargetPos(i int) bool {
	return len(b.Decl.Args()) == i
}

func init() {
	BuiltinMap = map[string]*Builtin{}
	for _, b := range DefaultBuiltins {
		RegisterBuiltin(b)
	}
}
