package main

import (
	"bytes"
	"os/exec"
	"strings"
)

type commander interface {
	Command(name string, arg ...string) runner
	PipeCommands(c1 runner, c2 runner) string
}

type commandHelper struct {
}

func (c *commandHelper) Command(name string, arg ...string) runner {
	return &shellRunner{cmd: exec.Command(name, arg...)}
}

func (c *commandHelper) PipeCommands(r1 runner, r2 runner) string {
	var buf bytes.Buffer
	c1 := r1.(*shellRunner)
	c2 := r2.(*shellRunner)
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

type runner interface {
	CombinedOutput() ([]byte, error)
	Output() ([]byte, error)
	SetWorkingDir(path string)
}

type shellRunner struct {
	cmd        *exec.Cmd
	workingDir string
}

func (r *shellRunner) CombinedOutput() ([]byte, error) {
	return r.cmd.CombinedOutput()
}

func (r *shellRunner) Output() ([]byte, error) {
	return r.cmd.Output()
}

func (r *shellRunner) SetWorkingDir(path string) {
	r.cmd.Dir = path
}
