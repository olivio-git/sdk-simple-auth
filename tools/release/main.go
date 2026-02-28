package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ANSI colors
const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	gray   = "\033[90m"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	bump := os.Args[1]
	if bump == "-h" || bump == "--help" || bump == "help" {
		printUsage()
		os.Exit(0)
	}
	if bump != "patch" && bump != "minor" && bump != "major" {
		errorf("bump type must be patch, minor or major — got %q", bump)
	}

	// Resolve project root (directory of this binary / go run context)
	root, err := findProjectRoot()
	if err != nil {
		errorf("could not find package.json: %v", err)
	}

	currentVersion := readVersion(root)
	step(1, "Current version: "+bold+currentVersion+reset)

	// 1. Bump version (creates git tag + version commit via npm)
	step(2, "Bumping version (npm version "+bump+")")
	run(root, "npm", "version", bump, "--no-git-tag-version")

	newVersion := readVersion(root)
	infof("New version: %s%s%s", bold, newVersion, reset)

	// 2. Stage package.json + package-lock.json and commit
	step(3, "Committing version bump")
	run(root, "git", "add", "package.json", "package-lock.json")
	run(root, "git", "commit", "-m", "chore: release v"+newVersion)
	run(root, "git", "tag", "v"+newVersion)

	// 3. Build
	step(4, "Building all formats")
	run(root, "npm", "run", "build")

	// 4. Push commits + tags
	step(5, "Pushing to remote")
	run(root, "git", "push")
	run(root, "git", "push", "--tags")

	// 5. Publish to npm
	step(6, "Publishing to npm")
	run(root, "npm", "publish")

	fmt.Printf("\n%s%s Released v%s successfully!%s\n\n", bold, green, newVersion, reset)
}

// ---------- helpers ----------

func step(n int, msg string) {
	fmt.Printf("\n%s[%d]%s %s%s%s\n", cyan+bold, n, reset, bold, msg, reset)
}

func infof(format string, args ...any) {
	fmt.Printf("    "+format+"\n", args...)
}

func errorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, red+"error: "+reset+format+"\n", args...)
	os.Exit(1)
}

func run(dir string, name string, args ...string) {
	fmt.Printf("  %s$ %s %s%s\n", gray, name, strings.Join(args, " "), reset)
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		errorf("command failed: %s %s\n  %v", name, strings.Join(args, " "), err)
	}
}

func findProjectRoot() (string, error) {
	// Walk up from cwd looking for package.json
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(dir + "/package.json"); err == nil {
			return dir, nil
		}
		parent := dir[:strings.LastIndex(dir, "/")]
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("package.json not found")
}

func readVersion(root string) string {
	data, err := os.ReadFile(root + "/package.json")
	if err != nil {
		errorf("cannot read package.json: %v", err)
	}
	var pkg struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		errorf("cannot parse package.json: %v", err)
	}
	return pkg.Version
}

func printUsage() {
	fmt.Printf(`%srelease%s — SDK release automation

%sUsage:%s
  release <bump>

%sBump types:%s
  patch   Bug fixes            (2.1.1 → 2.1.2)
  minor   New features         (2.1.1 → 2.2.0)
  major   Breaking changes     (2.1.1 → 3.0.0)

%sWhat it does:%s
  1. npm version <bump>   — bumps package.json
  2. git commit + tag     — commits the version bump
  3. npm run build        — builds all dist formats
  4. git push + tags      — pushes to remote
  5. npm publish          — publishes to npm

%sExample:%s
  release minor
`, bold, reset, bold, reset, bold, reset, bold, reset, bold, reset)
}
