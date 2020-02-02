package main

import (
	"bytes"
	"strings"
	"testing"
)

type testCase struct {
	bytes    []byte
	expected string
}

func TestAdd(t *testing.T) {
	tcs := []testCase{
		{[]byte{0x48, 0x83, 0xc0, 0x01}, "ADD rax, 0x01\n"},
		{[]byte{0x49, 0x83, 0xc0, 0x01}, "ADD r8, 0x01\n"},
		{[]byte{0x49, 0x83, 0xc4, 0x01}, "ADD r12, 0x01\n"},
	}
	testTestCases(t, tcs)
}

func TestXor(t *testing.T) {
	tcs := []testCase{
		{[]byte{0x48, 0x83, 0xf3, 0x01}, "XOR rbx, 0x01\n"},
		{[]byte{0x49, 0x83, 0xf4, 0x01}, "XOR r12, 0x01\n"},
	}
	testTestCases(t, tcs)
}

func TestMov(t *testing.T) {
	tcs := []testCase{
		{[]byte{0xb8, 0xef, 0xbe, 0xad, 0xde}, "MOV rax, 0xdeadbeef\n"},
		{[]byte{0x41, 0xbc, 0xef, 0xbe, 0xad, 0xde}, "MOV r12, 0xdeadbeef\n"},
		{[]byte{0x48, 0xb8, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00}, "MOV rax, 0xdeadbeefdead\n"},
		{[]byte{0x48, 0xb8, 0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde}, "MOV rax, 0xdeadbeefdeadbeef\n"},
		{[]byte{0x48, 0xb8, 0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x0a}, "MOV rax, 0x0abcdef012345678\n"},
		{[]byte{0x48, 0x89, 0xc0}, "MOV rax, rax\n"},
		{[]byte{0x48, 0x89, 0xd8}, "MOV rax, rbx\n"},
		{[]byte{0x48, 0x89, 0xc3}, "MOV rbx, rax\n"},
		{[]byte{0xb8, 0x01, 0x00, 0x00, 0x00}, "MOV rax, 0x01\n"},
		{[]byte{0x41, 0xbc, 0x01, 0x00, 0x00, 0x00}, "MOV r12, 0x01\n"},
		{[]byte{0x41, 0xbc, 0x02, 0x00, 0x00, 0x00}, "MOV r12, 0x02\n"},
		{[]byte{0x4d, 0x89, 0xc4}, "MOV r12, r8\n"},
		{[]byte{0x4d, 0x89, 0xcc}, "MOV r12, r9\n"},
		{[]byte{0x4c, 0x89, 0xe0}, "MOV rax, r12\n"},
		{[]byte{0x49, 0x89, 0xc4}, "MOV r12, rax\n"},
	}
	testTestCases(t, tcs)
}

func testTestCases(t *testing.T, tcs []testCase) {
	var prog []byte
	progOutput := make([]string, len(tcs))
	for i, tc := range tcs {
		b := &bytes.Buffer{}
		if err := parseExecProg(tc.bytes, b); err != nil {
			t.Errorf("%d - %s: unable to parse prog 0x%x: %v", i+1, tc.expected, tc.bytes, err)
			continue
		}
		if b.String() != tc.expected {
			t.Errorf("%d: 0x%x %q was not expected %q", i+1, tc.bytes, b.String(), tc.expected)
			continue
		}
		prog = append(prog, tc.bytes...)
		progOutput[i] = tc.expected
	}

	b := &bytes.Buffer{}
	if err := parseExecProg(prog, b); err != nil {
		t.Fatalf("all: unable to parse prog 0x%x: %v", prog, err)
	}
	expected := strings.Join(progOutput, "")
	if b.String() != expected {
		t.Errorf("0x%X %q was not expected %q", prog, b.String(), expected)
	}
}
