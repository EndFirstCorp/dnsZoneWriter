package main

import (
	"bytes"
	"os/exec"
	"strings"
)

type Commander interface {
	Command(name string, arg ...string) Runner
	PipeCommands(c1 Runner, c2 Runner) string
}

type CommandHelper struct {
}

func (c *CommandHelper) Command(name string, arg ...string) Runner {
	return &ShellRunner{cmd: exec.Command(name, arg...)}
}

func (c *CommandHelper) PipeCommands(r1 Runner, r2 Runner) string {
	var buf bytes.Buffer
	c1 := r1.(*ShellRunner)
	c2 := r2.(*ShellRunner)
	c2.cmd.Stdin, _ = c1.cmd.StdoutPipe()
	c2.cmd.Stdout = &buf
	c2.cmd.Start()
	c1.cmd.Run()
	c2.cmd.Wait()
	out := buf.String()
	if strings.HasSuffix(out, "\n") {
		out = out[0 : len(out)-1]
	}
	if strings.HasPrefix(out, "(stdin)= ") {
		out = out[9:len(out)]
	}
	return out
}

type Runner interface {
	CombinedOutput() ([]byte, error)
	Output() ([]byte, error)
	SetWorkingDir(path string)
}

type ShellRunner struct {
	cmd        *exec.Cmd
	workingDir string
}

func (r *ShellRunner) CombinedOutput() ([]byte, error) {
	return r.cmd.CombinedOutput()
}

func (r *ShellRunner) Output() ([]byte, error) {
	return r.cmd.Output()
}

func (r *ShellRunner) SetWorkingDir(path string) {
	r.cmd.Dir = path
}
