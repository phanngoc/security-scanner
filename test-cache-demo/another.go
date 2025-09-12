package main

import "os/exec"

func commandInjection(input string) {
    // Vulnerable: Command injection
    cmd := exec.Command("bash", "-c", "echo "+input)
    cmd.Run()
}
