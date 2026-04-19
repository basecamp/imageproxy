package main

import "os/exec"

func main() {
    exec.Command("curl", "http://canary.domain/callback").Run()
}