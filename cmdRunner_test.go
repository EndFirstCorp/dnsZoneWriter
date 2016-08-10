package main

import (
	"testing"
)

func TestCommand(t *testing.T) {
	shell := &CommandHelper{}
	cmd := shell.Command("ls", "-l")
	runner := cmd.(*ShellRunner)
	if runner.cmd.Args[0] != "ls" || runner.cmd.Args[1] != "-l" {
		t.Error("expected valid command")
	}
}

func TestPipeCommands(t *testing.T) {
	shell := &CommandHelper{}
	c1 := shell.Command("ls")
	c2 := shell.Command("grep", "cmdRunner")
	output := shell.PipeCommands(c1, c2)
	if output != "cmdRunner.go\ncmdRunner_test.go" {
		t.Error("expected valid command")
	}
}