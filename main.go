//go:build windows

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	appName    = "GBZapCleaner"
	appVersion = "2.0"

	// SHA-256 of the malicious TiWorker.exe sample supplied for analysis.
	badSHA256 = "9bd6d3998c1c8a9c173b6eab19819ada9cc88a87f77b4c9e96b8f4d8c0d38279"
	badSize   = int64(3592990)

	fileAttributeReadonly = 0x00000001
	fileAttributeHidden   = 0x00000002
	fileAttributeSystem   = 0x00000004
	fileAttributeNormal   = 0x00000080

	movefileDelayUntilReboot = 0x00000004
	stdOutputHandle          = ^uintptr(10) // (DWORD)-11
	enableVirtualTerminal    = 0x0004
)

var (
	stdinReader = bufio.NewReader(os.Stdin)

	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	shell32                = syscall.NewLazyDLL("shell32.dll")
	procGetFileAttributes  = kernel32.NewProc("GetFileAttributesW")
	procSetFileAttributes  = kernel32.NewProc("SetFileAttributesW")
	procMoveFileEx         = kernel32.NewProc("MoveFileExW")
	procGetStdHandle       = kernel32.NewProc("GetStdHandle")
	procGetConsoleMode     = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode     = kernel32.NewProc("SetConsoleMode")
	procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
	procSetConsoleCP       = kernel32.NewProc("SetConsoleCP")
	procShellExecuteW      = shell32.NewProc("ShellExecuteW")
	procIsUserAnAdmin      = shell32.NewProc("IsUserAnAdmin")
)

var (
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	red     = "\x1b[31m"
	green   = "\x1b[32m"
	yellow  = "\x1b[33m"
	blue    = "\x1b[34m"
	magenta = "\x1b[35m"
	cyan    = "\x1b[36m"
	white   = "\x1b[37m"
)

type confidence int

const (
	confSuspicious confidence = iota
	confHigh
	confConfirmed
)

type finding struct {
	Path        string
	Size        int64
	SHA256      string
	ExactHash   bool
	UniqueMark  bool
	FamilyCombo bool
	MarkerList  []string
	Hidden      bool
	System      bool
	Readonly    bool
	UPX         bool
	TrustedWin  bool
	Score       int
	Confidence  confidence
	Reasons     []string
}

type stats struct {
	FilesSeen  int64
	Candidates int64
	Denied     int64
	Errors     int64
	Started    time.Time
}

type scanOptions struct {
	Full       bool
	CustomRoot []string
	NoColor    bool
}

type fileLogger struct {
	f *os.File
}

func (l *fileLogger) printf(format string, args ...any) {
	if l == nil || l.f == nil {
		return
	}
	_, _ = fmt.Fprintf(l.f, format, args...)
	_ = l.f.Sync()
}

func main() {
	if runtime.GOOS != "windows" {
		fmt.Println("This build is for Windows.")
		return
	}

	enableUTF8Console()
	colorOK := enableANSI()

	opts, showHelp := parseArgs(os.Args[1:])
	if showHelp {
		printHelp()
		return
	}
	if opts.NoColor || os.Getenv("NO_COLOR") != "" {
		colorOK = false
	}
	if !colorOK {
		disableColors()
	}

	clearScreen()
	printBanner()

	if !isAdmin() {
		warn("Запущено без прав администратора.")
		fmt.Printf("  Для удаления защищённых файлов нужны повышенные права.\n")
		if askYesNo("Перезапустить утилиту от имени администратора?", true) {
			if err := relaunchAsAdmin(); err != nil {
				errorLine("Не удалось запросить повышение прав: %v", err)
				fmt.Println("  Запусти EXE через ПКМ → Запуск от имени администратора.")
				pause()
				return
			}
			return
		}
		fmt.Println()
	}

	if len(opts.CustomRoot) == 0 && !hasModeArg(os.Args[1:]) {
		opts = interactiveMode(opts)
	}

	roots := opts.CustomRoot
	if len(roots) == 0 {
		if opts.Full {
			roots = existingDriveRoots()
		} else {
			roots = quickRoots()
		}
	}
	roots = uniqueExistingRoots(roots)
	if len(roots) == 0 {
		errorLine("Не найдено ни одной доступной папки для сканирования.")
		pause()
		return
	}

	logPath := defaultLogPath()
	lf, _ := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if lf != nil {
		defer lf.Close()
	}
	log := &fileLogger{f: lf}
	log.printf("\n=== %s v%s %s ===\n", appName, appVersion, time.Now().Format(time.RFC3339))
	log.printf("Known malicious SHA-256: %s\n", badSHA256)
	log.printf("Roots: %s\n", strings.Join(roots, "; "))

	printScanPlan(roots, opts.Full, logPath)
	fmt.Println()
	info("Сканирование началось. Файлы не запускаются и не изменяются на этом этапе.")

	findings, st := scan(roots, opts.Full, log)
	finishProgress(st, len(findings))
	fmt.Println()

	if len(findings) == 0 {
		success("Совпадений не найдено.")
		fmt.Printf("  Просмотрено: %s файлов • кандидатов: %s • ошибок доступа: %s\n",
			formatInt(st.FilesSeen), formatInt(st.Candidates), formatInt(st.Denied))
		fmt.Printf("  Лог: %s\n", logPath)
		pause()
		return
	}

	sortFindings(findings)
	printFindings(findings)
	logFindings(log, findings)

	selected := chooseDeletion(findings)
	if len(selected) == 0 {
		info("Удаление отменено. Ни один найденный файл не изменён.")
		fmt.Printf("  Лог: %s\n", logPath)
		pause()
		return
	}

	fmt.Println()
	warn("Будет удалено файлов: %d", len(selected))
	for _, idx := range selected {
		fmt.Printf("  %s#%d%s %s\n", dim, idx+1, reset, findings[idx].Path)
	}
	fmt.Println()
	if !askYesNo("Подтвердить удаление выбранных файлов?", false) {
		info("Удаление отменено.")
		pause()
		return
	}

	deleted, scheduled, failed := 0, 0, 0
	fmt.Println()
	section("Очистка")
	for _, idx := range selected {
		f := findings[idx]
		fmt.Printf("  %s→%s %s\n", cyan, reset, f.Path)
		result, err := removeFile(f.Path, log)
		if err != nil {
			failed++
			errorLine("    не удалось удалить: %v", err)
			continue
		}
		switch result {
		case "deleted":
			deleted++
			success("    удалено")
		case "scheduled":
			scheduled++
			warn("    файл занят → удаление запланировано после перезагрузки")
		}
	}

	fmt.Println()
	section("Готово")
	fmt.Printf("  Удалено: %s%d%s   После перезагрузки: %s%d%s   Ошибок: %s%d%s\n",
		green, deleted, reset, yellow, scheduled, reset, red, failed, reset)
	if scheduled > 0 {
		warn("Перезагрузи Windows, чтобы завершить удаление заблокированных файлов.")
	}
	fmt.Printf("  Лог: %s\n", logPath)
	pause()
}

func parseArgs(args []string) (scanOptions, bool) {
	var o scanOptions
	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "--full", "/full":
			o.Full = true
		case "--quick", "/quick":
			o.Full = false
		case "--root":
			if i+1 < len(args) {
				i++
				o.CustomRoot = append(o.CustomRoot, args[i])
			}
		case "--no-color":
			o.NoColor = true
		case "--help", "-h", "/?":
			return o, true
		}
	}
	return o, false
}

func hasModeArg(args []string) bool {
	for _, a := range args {
		a = strings.ToLower(a)
		if a == "--quick" || a == "/quick" || a == "--full" || a == "/full" || a == "--root" {
			return true
		}
	}
	return false
}

func interactiveMode(o scanOptions) scanOptions {
	section("Режим сканирования")
	fmt.Printf("  %s1%s  Быстрое       Профиль пользователя, ProgramData, Temp %s(рекомендуется)%s\n", cyan, reset, dim, reset)
	fmt.Printf("  %s2%s  Полное        Локальные диски C:–Z:; может занять заметное время\n", cyan, reset)
	fmt.Printf("  %s3%s  Свой путь     Сканировать указанную папку или диск\n", cyan, reset)
	fmt.Println()
	for {
		fmt.Printf("  %s›%s Выбор [1]: ", cyan, reset)
		s := readLine()
		if s == "" || s == "1" {
			o.Full = false
			return o
		}
		if s == "2" {
			o.Full = true
			return o
		}
		if s == "3" {
			fmt.Printf("  %s›%s Путь: ", cyan, reset)
			p := strings.Trim(strings.TrimSpace(readLine()), "\"")
			if p == "" {
				warn("Путь пустой.")
				continue
			}
			o.CustomRoot = []string{p}
			return o
		}
		warn("Введите 1, 2 или 3.")
	}
}

func printScanPlan(roots []string, full bool, logPath string) {
	section("Параметры")
	mode := "Быстрое"
	if full {
		mode = "Полное"
	}
	fmt.Printf("  %-14s %s\n", "Режим", mode)
	fmt.Printf("  %-14s %s\n", "Сигнатура", badSHA256[:16]+"…")
	fmt.Printf("  %-14s %s\n", "Корни", strings.Join(roots, ", "))
	fmt.Printf("  %-14s %s\n", "Лог", logPath)
	fmt.Printf("  %-14s %s\n", "Политика", "сначала список → затем явное подтверждение удаления")
}

func scan(roots []string, full bool, log *fileLogger) ([]finding, stats) {
	st := stats{Started: time.Now()}
	var out []finding
	seen := map[string]bool{}
	self := executablePathLower()
	lastDraw := time.Now().Add(-time.Second)
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spin := 0

	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if errors.Is(walkErr, os.ErrPermission) {
					st.Denied++
				} else {
					st.Errors++
				}
				return nil
			}
			if d.IsDir() {
				if shouldSkipDir(path, full) {
					return fs.SkipDir
				}
				return nil
			}

			st.FilesSeen++
			if time.Since(lastDraw) >= 90*time.Millisecond {
				progressLine(spinner[spin%len(spinner)], st, len(out), path)
				spin++
				lastDraw = time.Now()
			}

			if self != "" {
				if a, err := filepath.Abs(path); err == nil && strings.ToLower(filepath.Clean(a)) == self {
					return nil
				}
			}
			info, err := d.Info()
			if err != nil || info.Size() <= 0 || !candidateForInspection(path, info) {
				return nil
			}
			st.Candidates++
			f, err := inspectFile(path, info)
			if err != nil {
				if errors.Is(err, os.ErrPermission) {
					st.Denied++
				} else {
					st.Errors++
				}
				return nil
			}
			if len(f.Reasons) == 0 {
				return nil
			}
			key := strings.ToLower(filepath.Clean(path))
			if seen[key] {
				return nil
			}
			seen[key] = true
			out = append(out, f)
			log.printf("DETECTED [%s] %s sha256=%s reasons=%s\n", confidenceName(f.Confidence), f.Path, f.SHA256, strings.Join(f.Reasons, "; "))
			return nil
		})
	}
	return out, st
}

func inspectFile(path string, info fs.FileInfo) (finding, error) {
	f := finding{Path: path, Size: info.Size()}
	attrs, _ := getAttributes(path)
	f.Hidden = attrs&fileAttributeHidden != 0
	f.System = attrs&fileAttributeSystem != 0
	f.Readonly = attrs&fileAttributeReadonly != 0
	f.TrustedWin = isTrustedTiWorkerPath(path)

	h, err := os.Open(path)
	if err != nil {
		return f, err
	}
	defer h.Close()

	first := make([]byte, 8192)
	n1, _ := h.Read(first)
	first = first[:n1]
	mz := len(first) >= 2 && first[0] == 'M' && first[1] == 'Z'
	if !mz && info.Size() != badSize {
		return f, nil
	}

	tailLen := int64(64 * 1024)
	if info.Size() < tailLen {
		tailLen = info.Size()
	}
	tail := make([]byte, tailLen)
	_, _ = h.Seek(info.Size()-tailLen, io.SeekStart)
	n2, _ := io.ReadFull(h, tail)
	if n2 > 0 {
		tail = tail[:n2]
	}
	probe := make([]byte, 0, len(first)+len(tail))
	probe = append(probe, first...)
	probe = append(probe, tail...)

	markers := []string{"GBZAP-PACK-UNIQUE", "GBZAPUNQ2", "zapRETDiscORd", "flowseal", "s.exe"}
	for _, m := range markers {
		if bytesContains(probe, []byte(m)) {
			f.MarkerList = append(f.MarkerList, m)
		}
	}
	f.UPX = bytesContains(first, []byte("UPX0")) || bytesContains(first, []byte("UPX1")) || bytesContains(first, []byte("UPX!"))
	f.UniqueMark = containsString(f.MarkerList, "GBZAP-PACK-UNIQUE") || containsString(f.MarkerList, "GBZAPUNQ2")
	f.FamilyCombo = containsString(f.MarkerList, "zapRETDiscORd") && containsString(f.MarkerList, "flowseal")

	name := strings.ToLower(filepath.Base(path))
	nameLooks := strings.Contains(name, "tiworker")
	if nameLooks {
		f.Score += 2
	}
	if f.Hidden && f.System {
		f.Score += 2
	}
	if f.UPX {
		f.Score++
	}
	if info.Size() >= 3300000 && info.Size() <= 3900000 {
		f.Score++
	}
	if !f.TrustedWin {
		f.Score++
	}
	if f.FamilyCombo {
		f.Score += 3
	}
	if f.UniqueMark {
		f.Score += 8
	}

	shouldHash := info.Size() == badSize || f.UniqueMark || f.FamilyCombo || nameLooks || f.Score >= 5
	if shouldHash {
		if sum, err := sha256File(path); err == nil {
			f.SHA256 = sum
			f.ExactHash = strings.EqualFold(sum, badSHA256)
		}
	}

	if f.ExactHash {
		f.Confidence = confConfirmed
		f.Reasons = append(f.Reasons, "точный SHA-256 вредоносного образца")
	}
	if f.UniqueMark {
		if f.Confidence < confConfirmed {
			f.Confidence = confConfirmed
		}
		f.Reasons = append(f.Reasons, "уникальные маркеры GBZAP-family")
	}
	if !f.ExactHash && !f.UniqueMark && f.FamilyCombo {
		f.Confidence = confHigh
		f.Reasons = append(f.Reasons, "связка маркеров zapRETDiscORd + flowseal")
	}

	// Heuristics are intentionally conservative. A genuine TiWorker in WinSxS is not
	// reported from heuristic evidence alone. Hash/unique markers can still override.
	if len(f.Reasons) == 0 && !f.TrustedWin && nameLooks && f.Hidden && f.System && f.UPX && f.Score >= 6 {
		f.Confidence = confSuspicious
		f.Reasons = append(f.Reasons, "TiWorker вне WinSxS + Hidden/System + UPX")
	}
	return f, nil
}

func printFindings(findings []finding) {
	section(fmt.Sprintf("Обнаружено: %d", len(findings)))
	fmt.Printf("  %s%-4s %-12s %-8s %-6s  %-34s  %s%s\n", bold, "ID", "УРОВЕНЬ", "РАЗМЕР", "ATTR", "ПРИЧИНА", "ФАЙЛ", reset)
	fmt.Printf("  %s%s%s\n", dim, strings.Repeat("─", 116), reset)
	for i, f := range findings {
		level, c := confidenceLabel(f.Confidence)
		attrs := attrLabel(f)
		reason := strings.Join(f.Reasons, "; ")
		if len([]rune(reason)) > 34 {
			reason = truncateRunes(reason, 33) + "…"
		}
		fmt.Printf("  %-4s %s%-12s%s %-8s %-6s  %-34s  %s\n",
			fmt.Sprintf("#%d", i+1), c, level, reset, humanSize(f.Size), attrs, reason, f.Path)
	}
	fmt.Println()
	for i, f := range findings {
		fmt.Printf("  %s#%d%s %s\n", bold, i+1, reset, f.Path)
		fmt.Printf("     SHA-256 : %s\n", valueOrDash(f.SHA256))
		fmt.Printf("     Маркеры : %s\n", valueOrDash(strings.Join(f.MarkerList, ", ")))
		fmt.Printf("     Атрибуты: Hidden=%v  System=%v  Read-only=%v  UPX=%v\n", f.Hidden, f.System, f.Readonly, f.UPX)
		fmt.Printf("     Причина : %s\n", strings.Join(f.Reasons, "; "))
		if f.Confidence == confSuspicious {
			fmt.Printf("     %s! Эвристика: перед удалением проверь путь и хэш.%s\n", yellow, reset)
		}
		fmt.Println()
	}
}

func chooseDeletion(findings []finding) []int {
	section("Действие")
	confirmed := indexesByMinConfidence(findings, confConfirmed)
	high := indexesExactConfidence(findings, confHigh)
	susp := indexesExactConfidence(findings, confSuspicious)

	fmt.Printf("  %sC%s  Удалить только CONFIRMED (%d) %s(рекомендуется)%s\n", cyan, reset, len(confirmed), dim, reset)
	fmt.Printf("  %sS%s  Выбрать ID вручную (пример: 1,3-5)\n", cyan, reset)
	fmt.Printf("  %sA%s  Выбрать все найденные (%d)\n", cyan, reset, len(findings))
	fmt.Printf("  %sN%s  Ничего не удалять\n", cyan, reset)
	if len(high) > 0 || len(susp) > 0 {
		fmt.Printf("\n  %sПримечание:%s HIGH/SUSPICIOUS не входят в режим C и требуют ручного выбора.\n", yellow, reset)
	}
	fmt.Println()

	for {
		fmt.Printf("  %s›%s Выбор [C]: ", cyan, reset)
		s := strings.TrimSpace(strings.ToLower(readLine()))
		if s == "" || s == "c" {
			if len(confirmed) == 0 {
				warn("CONFIRMED-совпадений нет. Используй S для ручного выбора.")
				continue
			}
			return confirmed
		}
		switch s {
		case "n":
			return nil
		case "a":
			idx := make([]int, len(findings))
			for i := range idx {
				idx[i] = i
			}
			return idx
		case "s":
			fmt.Printf("  %s›%s ID: ", cyan, reset)
			raw := strings.TrimSpace(readLine())
			idx, err := parseSelection(raw, len(findings))
			if err != nil {
				errorLine("Некорректный список: %v", err)
				continue
			}
			return idx
		default:
			warn("Введите C, S, A или N.")
		}
	}
}

func parseSelection(s string, max int) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("список пуст")
	}
	set := map[int]bool{}
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			ab := strings.SplitN(part, "-", 2)
			if len(ab) != 2 {
				return nil, errors.New("неверный диапазон")
			}
			a, err1 := strconv.Atoi(strings.TrimSpace(ab[0]))
			b, err2 := strconv.Atoi(strings.TrimSpace(ab[1]))
			if err1 != nil || err2 != nil || a < 1 || b < 1 || a > b || b > max {
				return nil, fmt.Errorf("диапазон %q вне 1..%d", part, max)
			}
			for n := a; n <= b; n++ {
				set[n-1] = true
			}
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > max {
			return nil, fmt.Errorf("ID %q вне 1..%d", part, max)
		}
		set[n-1] = true
	}
	out := make([]int, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Ints(out)
	if len(out) == 0 {
		return nil, errors.New("ничего не выбрано")
	}
	return out, nil
}

func removeFile(path string, log *fileLogger) (string, error) {
	// Hidden/System/Read-only attributes are not security boundaries. Clear them first.
	_ = clearProtectionAttributes(path)
	if err := os.Remove(path); err == nil {
		log.printf("REMOVED %s\n", path)
		return "deleted", nil
	}

	// If NTFS ACLs/ownership block deletion, take ownership and grant Administrators + user full control.
	takeOwnership(path)
	_ = clearProtectionAttributes(path)
	if err := os.Remove(path); err == nil {
		log.printf("REMOVED_AFTER_ACL_FIX %s\n", path)
		return "deleted", nil
	}

	// Locked executable: ask Windows to remove it on the next boot.
	if err := scheduleDeleteOnReboot(path); err == nil {
		log.printf("SCHEDULED_DELETE_ON_REBOOT %s\n", path)
		return "scheduled", nil
	}
	return "", errors.New("удаление и постановка на удаление после перезагрузки не удались")
}

func candidateForInspection(path string, info fs.FileInfo) bool {
	if info.Size() > 256*1024*1024 {
		return false
	}
	n := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))
	if strings.Contains(n, "tiworker") || info.Size() == badSize {
		return true
	}
	switch ext {
	case ".exe", ".dll", ".scr", ".com", ".bin", ".tmp":
		return true
	}
	return false
}

func shouldSkipDir(path string, full bool) bool {
	p := strings.ToLower(filepath.Clean(path))
	base := strings.ToLower(filepath.Base(p))
	if base == "$recycle.bin" || base == "system volume information" || base == "gbzapcleaner_quarantine" {
		return true
	}
	if strings.Contains(p, `\program files\windowsapps`) {
		return true
	}
	if full {
		// Huge Windows stores are skipped for performance and false-positive safety.
		// The genuine TiWorker normally lives under WinSxS. The scanner still checks
		// copies elsewhere, including files carrying Hidden/System attributes.
		if strings.Contains(p, `\windows\winsxs`) ||
			strings.Contains(p, `\windows\installer`) ||
			strings.Contains(p, `\windows\softwaredistribution\download`) {
			return true
		}
	}
	return false
}

func quickRoots() []string {
	var roots []string
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, home)
	}
	for _, k := range []string{"PROGRAMDATA", "TEMP", "TMP"} {
		if v := os.Getenv(k); v != "" {
			roots = append(roots, v)
		}
	}
	if w := os.Getenv("WINDIR"); w != "" {
		roots = append(roots, filepath.Join(w, "Temp"))
	}
	if sd := os.Getenv("SystemDrive"); sd != "" {
		roots = append(roots, filepath.Join(sd+`\`, "Users", "Public"))
	}
	return roots
}

func existingDriveRoots() []string {
	var roots []string
	for c := 'C'; c <= 'Z'; c++ {
		r := fmt.Sprintf("%c:\\", c)
		if st, err := os.Stat(r); err == nil && st.IsDir() {
			roots = append(roots, r)
		}
	}
	return roots
}

func uniqueExistingRoots(in []string) []string {
	m := map[string]string{}
	for _, r := range in {
		if r == "" {
			continue
		}
		if abs, err := filepath.Abs(r); err == nil {
			r = abs
		}
		r = filepath.Clean(r)
		st, err := os.Stat(r)
		if err != nil || !st.IsDir() {
			continue
		}
		m[strings.ToLower(r)] = r
	}
	out := make([]string, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func isTrustedTiWorkerPath(path string) bool {
	w := os.Getenv("WINDIR")
	if w == "" {
		return false
	}
	p := strings.ToLower(filepath.Clean(path))
	winsxs := strings.ToLower(filepath.Clean(filepath.Join(w, "WinSxS")))
	return strings.HasPrefix(p, winsxs+string(os.PathSeparator)) && strings.EqualFold(filepath.Base(path), "TiWorker.exe")
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func bytesContains(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		ok := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func getAttributes(path string) (uint32, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	r, _, e := procGetFileAttributes.Call(uintptr(unsafe.Pointer(p)))
	if r == 0xFFFFFFFF {
		if e != syscall.Errno(0) {
			return 0, e
		}
		return 0, errors.New("GetFileAttributesW failed")
	}
	return uint32(r), nil
}

func clearProtectionAttributes(path string) error {
	attrs, err := getAttributes(path)
	if err != nil {
		return err
	}
	attrs &^= fileAttributeReadonly | fileAttributeHidden | fileAttributeSystem
	if attrs == 0 {
		attrs = fileAttributeNormal
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	r, _, e := procSetFileAttributes.Call(uintptr(unsafe.Pointer(p)), uintptr(attrs))
	if r == 0 {
		if e != syscall.Errno(0) {
			return e
		}
		return errors.New("SetFileAttributesW failed")
	}
	return nil
}

func takeOwnership(path string) {
	_ = exec.Command("takeown.exe", "/F", path, "/A").Run()
	_ = exec.Command("icacls.exe", path, "/grant", "*S-1-5-32-544:F", "/C", "/Q").Run()
	if u := os.Getenv("USERNAME"); u != "" {
		_ = exec.Command("icacls.exe", path, "/grant", u+":F", "/C", "/Q").Run()
	}
}

func scheduleDeleteOnReboot(path string) error {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	r, _, e := procMoveFileEx.Call(uintptr(unsafe.Pointer(p)), 0, movefileDelayUntilReboot)
	if r == 0 {
		if e != syscall.Errno(0) {
			return e
		}
		return errors.New("MoveFileExW failed")
	}
	return nil
}

func isAdmin() bool {
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

func relaunchAsAdmin() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	args := quoteWindowsArgs(os.Args[1:])
	params, _ := syscall.UTF16PtrFromString(args)
	dir := filepath.Dir(exe)
	cwd, _ := syscall.UTF16PtrFromString(dir)
	r, _, callErr := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)),
		uintptr(unsafe.Pointer(cwd)),
		1,
	)
	if r <= 32 {
		if callErr != syscall.Errno(0) {
			return callErr
		}
		return fmt.Errorf("ShellExecuteW returned %d", r)
	}
	return nil
}

func quoteWindowsArgs(args []string) string {
	var out []string
	for _, a := range args {
		if strings.ContainsAny(a, " \t\"") {
			a = strings.ReplaceAll(a, `"`, `\"`)
			out = append(out, `"`+a+`"`)
		} else {
			out = append(out, a)
		}
	}
	return strings.Join(out, " ")
}

func enableUTF8Console() {
	procSetConsoleOutputCP.Call(65001)
	procSetConsoleCP.Call(65001)
}

func enableANSI() bool {
	h, _, _ := procGetStdHandle.Call(stdOutputHandle)
	if h == 0 || h == ^uintptr(0) {
		return false
	}
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return false
	}
	r, _, _ = procSetConsoleMode.Call(h, uintptr(mode|enableVirtualTerminal))
	return r != 0
}

func disableColors() {
	reset, bold, dim = "", "", ""
	red, green, yellow, blue, magenta, cyan, white = "", "", "", "", "", "", ""
}

func clearScreen() {
	if reset != "" {
		fmt.Print("\x1b[2J\x1b[H")
	}
}

func printBanner() {
	fmt.Printf("%s%s╭──────────────────────────────────────────────────────────────╮%s\n", bold, cyan, reset)
	fmt.Printf("%s%s│%s  GBZapCleaner %sv%s%s   targeted malware scanner / remover      %s│%s\n", bold, cyan, reset, dim, appVersion, reset, bold+cyan, reset)
	fmt.Printf("%s%s╰──────────────────────────────────────────────────────────────╯%s\n", bold, cyan, reset)
	fmt.Printf("%s  Сигнатурный + осторожный эвристический поиск. Удаление — только после подтверждения.%s\n\n", dim, reset)
}

func section(title string) {
	fmt.Printf("%s%s◆ %s%s\n", bold, cyan, title, reset)
}

func info(format string, args ...any) {
	fmt.Printf("%s●%s %s\n", blue, reset, fmt.Sprintf(format, args...))
}

func success(format string, args ...any) {
	fmt.Printf("%s✓%s %s\n", green, reset, fmt.Sprintf(format, args...))
}

func warn(format string, args ...any) {
	fmt.Printf("%s!%s %s\n", yellow, reset, fmt.Sprintf(format, args...))
}

func errorLine(format string, args ...any) {
	fmt.Printf("%s×%s %s\n", red, reset, fmt.Sprintf(format, args...))
}

func progressLine(spin string, st stats, found int, path string) {
	elapsed := time.Since(st.Started).Round(time.Second)
	short := path
	if len([]rune(short)) > 62 {
		short = "…" + truncateRunesFromEnd(short, 61)
	}
	fmt.Printf("\r\x1b[2K  %s%s%s  %s%s%s files  %s%d%s candidates  %s%d%s hits  %s  %s%s",
		cyan, spin, reset,
		bold, formatInt(st.FilesSeen), reset,
		dim, st.Candidates, reset,
		yellow, found, reset,
		elapsed,
		dim, short+reset)
}

func finishProgress(st stats, found int) {
	elapsed := time.Since(st.Started).Round(time.Second)
	fmt.Printf("\r\x1b[2K  %s✓%s  %s%s%s files  %s%d%s candidates  %s%d%s hits  %s\n",
		green, reset,
		bold, formatInt(st.FilesSeen), reset,
		dim, st.Candidates, reset,
		yellow, found, reset,
		elapsed)
}

func confidenceLabel(c confidence) (string, string) {
	switch c {
	case confConfirmed:
		return "CONFIRMED", red + bold
	case confHigh:
		return "HIGH", yellow + bold
	default:
		return "SUSPICIOUS", magenta
	}
}

func confidenceName(c confidence) string {
	switch c {
	case confConfirmed:
		return "CONFIRMED"
	case confHigh:
		return "HIGH"
	default:
		return "SUSPICIOUS"
	}
}

func attrLabel(f finding) string {
	var s strings.Builder
	if f.Hidden {
		s.WriteByte('H')
	}
	if f.System {
		s.WriteByte('S')
	}
	if f.Readonly {
		s.WriteByte('R')
	}
	if s.Len() == 0 {
		return "-"
	}
	return s.String()
}

func indexesByMinConfidence(findings []finding, min confidence) []int {
	var out []int
	for i, f := range findings {
		if f.Confidence >= min {
			out = append(out, i)
		}
	}
	return out
}

func indexesExactConfidence(findings []finding, c confidence) []int {
	var out []int
	for i, f := range findings {
		if f.Confidence == c {
			out = append(out, i)
		}
	}
	return out
}

func sortFindings(f []finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Confidence != f[j].Confidence {
			return f[i].Confidence > f[j].Confidence
		}
		return strings.ToLower(f[i].Path) < strings.ToLower(f[j].Path)
	})
}

func logFindings(log *fileLogger, findings []finding) {
	for i, f := range findings {
		log.printf("#%d [%s] %s\n  sha256=%s\n  markers=%s\n  attrs H=%v S=%v R=%v UPX=%v\n  reasons=%s\n",
			i+1, confidenceName(f.Confidence), f.Path, f.SHA256, strings.Join(f.MarkerList, ","), f.Hidden, f.System, f.Readonly, f.UPX, strings.Join(f.Reasons, "; "))
	}
}

func askYesNo(prompt string, defYes bool) bool {
	suffix := "[y/N]"
	if defYes {
		suffix = "[Y/n]"
	}
	for {
		fmt.Printf("  %s›%s %s %s: ", cyan, reset, prompt, suffix)
		s := strings.ToLower(strings.TrimSpace(readLine()))
		if s == "" {
			return defYes
		}
		if s == "y" || s == "yes" || s == "д" || s == "да" {
			return true
		}
		if s == "n" || s == "no" || s == "н" || s == "нет" {
			return false
		}
	}
}

func readLine() string {
	s, _ := stdinReader.ReadString('\n')
	return strings.TrimSpace(s)
}

func pause() {
	fmt.Printf("\n%sНажми Enter для выхода…%s", dim, reset)
	_, _ = stdinReader.ReadString('\n')
}

func printHelp() {
	fmt.Printf("%s v%s\n\n", appName, appVersion)
	fmt.Println("Usage:")
	fmt.Println("  GBZapCleaner.exe                interactive mode")
	fmt.Println("  GBZapCleaner.exe --quick        quick scan + interactive removal")
	fmt.Println("  GBZapCleaner.exe --full         full local-drive scan + interactive removal")
	fmt.Println(`  GBZapCleaner.exe --root "C:\path" scan one path + interactive removal`)
	fmt.Println("  GBZapCleaner.exe --no-color     disable ANSI colors")
}

func defaultLogPath() string {
	name := fmt.Sprintf("GBZapCleaner_%s.log", time.Now().Format("20060102_150405"))
	if home, err := os.UserHomeDir(); err == nil {
		desktop := filepath.Join(home, "Desktop")
		if st, err := os.Stat(desktop); err == nil && st.IsDir() {
			return filepath.Join(desktop, name)
		}
	}
	return filepath.Join(os.TempDir(), name)
}

func executablePathLower() string {
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	a, err := filepath.Abs(self)
	if err != nil {
		return ""
	}
	return strings.ToLower(filepath.Clean(a))
}

func humanSize(n int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case n >= GB:
		return fmt.Sprintf("%.1fG", float64(n)/GB)
	case n >= MB:
		return fmt.Sprintf("%.1fM", float64(n)/MB)
	case n >= KB:
		return fmt.Sprintf("%.1fK", float64(n)/KB)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func formatInt(n int64) string {
	s := strconv.FormatInt(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + " " + s[i:]
	}
	return s
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func truncateRunesFromEnd(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}

func valueOrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
