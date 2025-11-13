package cmd

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var (
	path         string
	extensions   []string
	deleteDup    bool
	dryRun       bool
	workers      int
	reportPath   string
	interactive  bool
	globalChoice string
	preferBase   bool // new flag for same-folder base name handling
	validChoices = map[string]bool{"k": true, "a": true, "s": true, "q": true, "": true}
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan folders for duplicate files",
	Long:  `Recursively scan a folder and find duplicate files by comparing file content hashes.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if path == "" {
			return fmt.Errorf("please provide a path to scan using --path")
		}
		if deleteDup && dryRun {
			return fmt.Errorf("--delete and --dry-run cannot be used together")
		}
		if globalChoice != "" && !validChoices[strings.ToLower(globalChoice)] {
			return fmt.Errorf("invalid value for --global-choice (must be one of k, a, s, q)")
		}
		return scanForDuplicates(path, extensions, deleteDup, dryRun, workers, reportPath, interactive, strings.ToLower(globalChoice), preferBase)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&path, "path", "p", "", "Root path to scan (required)")
	scanCmd.Flags().StringSliceVarP(&extensions, "ext", "e", []string{".jpg", ".jpeg", ".png"}, "File extensions to include")
	scanCmd.Flags().BoolVarP(&deleteDup, "delete", "d", false, "Delete duplicate files (keep one copy)")
	scanCmd.Flags().BoolVarP(&dryRun, "dry-run", "n", false, "Simulate deletion without removing files")
	scanCmd.Flags().IntVarP(&workers, "workers", "w", runtime.NumCPU(), "Number of concurrent hashing workers")
	scanCmd.Flags().StringVar(&reportPath, "report", "", "Path to save JSON report (optional)")
	scanCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Ask which duplicates to delete interactively")
	scanCmd.Flags().StringVar(&globalChoice, "global-choice", "", "Apply this choice to all groups (k=keep, a=auto delete, s=select manually, q=quit)")
	scanCmd.Flags().BoolVar(&preferBase, "prefer-base-name", true, "In same folder, keep base file name and delete numbered duplicates")
}

type fileInfo struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Action string `json:"action"` // kept, deleted, dry-run
}

type duplicateGroup struct {
	Hash  string     `json:"hash"`
	Files []fileInfo `json:"files"`
}

type report struct {
	ScannedAt        time.Time        `json:"scanned_at"`
	RootPath         string           `json:"root_path"`
	Extensions       []string         `json:"extensions"`
	TotalFiles       int              `json:"total_files"`
	DuplicateGroups  []duplicateGroup `json:"duplicate_groups"`
	TotalDupFiles    int              `json:"total_duplicate_files"`
	PotentialReclaim int64            `json:"potential_reclaimed_bytes"`
	ActualDeleted    int64            `json:"actual_deleted_bytes"`
}

func scanForDuplicates(root string, exts []string, delete, dry bool, workers int, reportFile string, interactive bool, globalChoice string, preferBase bool) error {
	var files []fileInfo

	fmt.Println("Scanning for files...")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if hasAllowedExt(path, exts) {
			files = append(files, fileInfo{Path: path, Size: info.Size(), Action: "kept"})
		}
		return nil
	})
	if err != nil {
		return err
	}

	fmt.Printf("Found %d matching files.\n", len(files))
	if len(files) == 0 {
		return nil
	}

	bar := progressbar.NewOptions(len(files),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(15),
		progressbar.OptionSetDescription("Hashing files..."),
		progressbar.OptionShowElapsedTimeOnFinish(),
	)

	type result struct {
		hash string
		info fileInfo
		err  error
	}

	fileCh := make(chan fileInfo)
	resultCh := make(chan result)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range fileCh {
				hash, err := hashFile(f.Path)
				resultCh <- result{hash: hash, info: f, err: err}
			}
		}()
	}

	go func() {
		for _, f := range files {
			fileCh <- f
		}
		close(fileCh)
		wg.Wait()
		close(resultCh)
	}()

	hashes := make(map[string][]fileInfo)
	for res := range resultCh {
		bar.Add(1)
		if res.err != nil {
			continue
		}
		hashes[res.hash] = append(hashes[res.hash], res.info)
	}

	fmt.Println("\nDuplicates found:")
	var totalDupFiles int
	var totalDupSize, actualDeleted int64
	var groups []duplicateGroup

	reader := bufio.NewReader(os.Stdin)

	for hash, infos := range hashes {
		if len(infos) > 1 {
			// Handle prefer-base-name in same folder
			if preferBase {
				infos = reorderByBaseName(infos)
			}

			fmt.Println("----")
			for i, f := range infos {
				fmt.Printf("[%d] %s (%s)\n", i+1, f.Path, formatSize(f.Size))
			}

			totalDupFiles += len(infos) - 1
			totalDupSize += sumSize(infos[1:])
			group := duplicateGroup{Hash: hash, Files: infos}

			// Modes
			if delete {
				deleteDuplicates(&group, infos, &actualDeleted)
			} else if dry {
				for i := range infos[1:] {
					f := &group.Files[i+1]
					fmt.Println("[Dry-run] Would delete:", f.Path)
					f.Action = "dry-run"
				}
			} else if globalChoice != "" {
				if !handleChoice(globalChoice, &group, infos, reader, &actualDeleted) {
					break
				}
			} else if interactive {
				fmt.Println("\nOptions:")
				fmt.Println("  [k] Keep all")
				fmt.Println("  [a] Auto delete duplicates (keep first)")
				fmt.Println("  [s] Select manually")
				fmt.Println("  [q] Quit")
				fmt.Print("Choose action (k/a/s/q): ")

				input, _ := reader.ReadString('\n')
				choice := strings.TrimSpace(strings.ToLower(input))

				if !handleChoice(choice, &group, infos, reader, &actualDeleted) {
					break
				}
			}

			groups = append(groups, group)
		}
	}

	fmt.Printf("\nScan complete.\n")
	saveReportIfRequested(reportFile, root, exts, files, groups, totalDupFiles, totalDupSize, actualDeleted)
	printSummary(groups, totalDupFiles, totalDupSize, actualDeleted)
	return nil
}

// Reorder files to keep base name first, then numbered/copy suffixes
func reorderByBaseName(files []fileInfo) []fileInfo {
	sort.SliceStable(files, func(i, j int) bool {
		baseI := stripNumberedSuffix(filepath.Base(files[i].Path))
		baseJ := stripNumberedSuffix(filepath.Base(files[j].Path))
		if baseI != baseJ {
			return baseI < baseJ
		}
		// Prefer shortest name first
		return len(filepath.Base(files[i].Path)) < len(filepath.Base(files[j].Path))
	})
	return files
}

var suffixRegexp = regexp.MustCompile(`(?i)(?:[_\s]?(\d+)|\s?\(\d+\)|_copy|_copy\d*)$`)

func stripNumberedSuffix(filename string) string {
	ext := filepath.Ext(filename)
	name := strings.TrimSuffix(filename, ext)
	return suffixRegexp.ReplaceAllString(name, "")
}

// --- existing helpers below ---

func handleChoice(choice string, group *duplicateGroup, infos []fileInfo, reader *bufio.Reader, actualDeleted *int64) bool {
	switch choice {
	case "a":
		deleteDuplicates(group, infos, actualDeleted)
	case "s":
		fmt.Print("Enter file numbers to delete (comma-separated): ")
		line, _ := reader.ReadString('\n')
		for _, part := range strings.Split(line, ",") {
			num, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil || num < 1 || num > len(infos) {
				fmt.Println("Invalid selection:", part)
				continue
			}
			f := &group.Files[num-1]
			if err := os.Remove(f.Path); err != nil {
				fmt.Println("Failed to delete:", f.Path, err)
			} else {
				fmt.Println("Deleted:", f.Path)
				f.Action = "deleted"
				*actualDeleted += f.Size
			}
		}
	case "q":
		fmt.Println("Aborted by user.")
		return false
	case "k", "":
		fmt.Println("Keeping all files in this group.")
	default:
		fmt.Println("Invalid choice; keeping all.")
	}
	return true
}

func deleteDuplicates(group *duplicateGroup, infos []fileInfo, actualDeleted *int64) {
	for i := range infos[1:] {
		f := &group.Files[i+1]
		if err := os.Remove(f.Path); err != nil {
			fmt.Println("Failed to delete:", f.Path, err)
		} else {
			fmt.Println("Deleted duplicate:", f.Path)
			f.Action = "deleted"
			*actualDeleted += f.Size
		}
	}
}

func saveReportIfRequested(reportFile, root string, exts []string, files []fileInfo, groups []duplicateGroup, totalDupFiles int, totalDupSize, actualDeleted int64) {
	if reportFile == "" {
		return
	}
	rep := report{
		ScannedAt:        time.Now(),
		RootPath:         root,
		Extensions:       exts,
		TotalFiles:       len(files),
		DuplicateGroups:  groups,
		TotalDupFiles:    totalDupFiles,
		PotentialReclaim: totalDupSize,
		ActualDeleted:    actualDeleted,
	}
	if err := saveReport(reportFile, rep); err != nil {
		fmt.Println("Failed to save report:", err)
	} else {
		fmt.Println("Report saved to:", reportFile)
	}
}

func saveReport(filename string, r report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func hasAllowedExt(path string, exts []string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	for _, e := range exts {
		if strings.ToLower(e) == ext {
			return true
		}
	}
	return false
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := md5.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func formatSize(bytes int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case bytes > GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes > MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes > KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func sumSize(files []fileInfo) int64 {
	var total int64
	for _, f := range files {
		total += f.Size
	}
	return total
}

func printSummary(groups []duplicateGroup, totalDupFiles int, totalDupSize, actualDeleted int64) {
	deleted := 0
	kept := 0
	var largestFile fileInfo
	for _, g := range groups {
		for _, f := range g.Files {
			if f.Size > largestFile.Size {
				largestFile = f
			}
			switch f.Action {
			case "deleted":
				deleted++
			case "kept", "":
				kept++
			case "dry-run":
				kept++
			}
		}
	}

	averageSize := int64(0)
	if totalDupFiles > 0 {
		averageSize = totalDupSize / int64(totalDupFiles)
	}

	fmt.Println("\n===== Summary =====")
	fmt.Printf("Duplicate groups: %d\n", len(groups))
	fmt.Printf("Total duplicate files: %d\n", totalDupFiles)
	fmt.Printf("Files deleted: %d\n", deleted)
	fmt.Printf("Files kept: %d\n", kept)
	fmt.Printf("Potential space to reclaim: %s\n", formatSize(totalDupSize))
	fmt.Printf("Actual reclaimed space: %s\n", formatSize(actualDeleted))
	fmt.Printf("Average size per duplicate file: %s\n", formatSize(averageSize))
	if largestFile.Path != "" {
		fmt.Printf("Largest duplicate file: %s (%s)\n", largestFile.Path, formatSize(largestFile.Size))
	}
	fmt.Println("===================")
}
