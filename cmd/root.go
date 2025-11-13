package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "dupfinder",
	Short: "Find and manage duplicate files on your system",
	Long:  `dupfinder scans directories to detect duplicate files by comparing content hashes.`,
}

// Execute runs the root command (called by main.go)
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
