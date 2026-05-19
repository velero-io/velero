package common

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
)

const (
	WorkerOSLinux   string = "linux"
	WorkerOSWindows string = "windows"
)

const (
	DefaultBSLName    string = "default"
	AdditionalBSLName string = "add-bsl"
)

type OsCommandLine struct {
	Cmd  string
	Args []string
}

func GetListByCmdPipes(ctx context.Context, cmdLines []*OsCommandLine) ([]string, error) {
	var buf bytes.Buffer
	var err error
	var cmds []*exec.Cmd

	for _, cmdline := range cmdLines {
		cmd := exec.CommandContext(ctx, cmdline.Cmd, cmdline.Args...)
		cmds = append(cmds, cmd)
	}
	fmt.Println(cmds)
	for i := 0; i < len(cmds); i++ {
		if i == len(cmds)-1 {
			break
		}
		cmds[i+1].Stdin, err = cmds[i].StdoutPipe()
		if err != nil {
			return nil, err
		}
	}
	cmds[len(cmds)-1].Stdout = &buf
	for i, v := range slices.Backward(cmds) {
		_ = v.Start()
		if i == 0 {
			_ = v.Run()
		}
	}
	for i := 1; i < len(cmds); i++ {
		_ = cmds[i].Wait()
	}

	scanner := bufio.NewScanner(&buf)
	var ret []string
	for scanner.Scan() {
		fmt.Printf("line: %s\n", scanner.Text())
		ret = append(ret, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ret, nil
}

func GetResourceWithLabel(ctx context.Context, namespace, resourceName string, labels map[string]string) ([]string, error) {
	labelStr := ""
	parts := make([]string, 0, len(labels))

	for key, value := range labels {
		strings.Join([]string{labelStr, key + "=" + value}, ",")
		parts = append(parts, key+"="+value)
	}
	labelStr = strings.Join(parts, ",")

	cmds := []*OsCommandLine{}
	cmd := &OsCommandLine{
		Cmd:  "kubectl",
		Args: []string{"get", resourceName, "--no-headers", "-n", namespace, "-l", labelStr},
	}
	cmds = append(cmds, cmd)

	cmd = &OsCommandLine{
		Cmd:  "awk",
		Args: []string{"{print $1}"},
	}
	cmds = append(cmds, cmd)

	return GetListByCmdPipes(ctx, cmds)
}

func CMDExecWithOutput(checkCMD *exec.Cmd) (*[]byte, error) {
	stdoutPipe, err := checkCMD.StdoutPipe()
	if err != nil {
		return nil, err
	}

	jsonBuf := make([]byte, 128*1024) // If the YAML is bigger than 64K, there's probably something bad happening

	err = checkCMD.Start()
	if err != nil {
		return nil, err
	}

	bytesRead, err := io.ReadFull(stdoutPipe, jsonBuf)

	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	if bytesRead == len(jsonBuf) {
		return nil, errors.New("yaml returned bigger than max allowed")
	}

	jsonBuf = jsonBuf[0:bytesRead]
	err = checkCMD.Wait()
	if err != nil {
		return nil, err
	}
	return &jsonBuf, err
}

func WriteToFile(content, fileName string) error {
	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println("fail to open file", err)
		return err
	}
	defer file.Close()

	write := bufio.NewWriter(file)
	_, err = write.WriteString(content)
	if err != nil {
		fmt.Println("fail to WriteString file", err)
		return err
	}
	err = write.Flush()
	if err != nil {
		fmt.Println("fail to Flush file", err)
		return err
	}
	return nil
}
func CreateFileContent(namespace, podName, volume string) string {
	return fmt.Sprintf("ns-%s pod-%s volume-%s", namespace, podName, volume)
}
