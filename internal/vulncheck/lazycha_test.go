// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// UniDoc fork: a differential test of the two routes of callGraph, the
// upstream one (an explicit CHA graph) and the lazy CHA one selected by
// GOVULNCHECK_LAZY_CHA=1.

package vulncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/test"
	"golang.org/x/vuln/internal/web"
)

// Environment of the helper process.
const (
	lazyCHAHelperDir = "GOVULNCHECK_LAZY_CHA_HELPER_DIR" // module to analyse
	lazyCHAHelperDB  = "GOVULNCHECK_LAZY_CHA_HELPER_DB"  // vulnerability database URL, or empty for no findings
	lazyCHAHelperOut = "GOVULNCHECK_LAZY_CHA_HELPER_OUT" // file the helper writes its lazyCHARun to
)

// lazyCHAExtraDirs is a list of further module directories, separated by
// the OS's path list separator, to run the differential test on, for
// example larger programs than the test modules. lazyCHAExtraDB is the
// vulnerability database URL for them; without it only the call graphs
// are compared.
const (
	lazyCHAExtraDirs = "GOVULNCHECK_LAZY_CHA_DIFF_DIRS"
	lazyCHAExtraDB   = "GOVULNCHECK_LAZY_CHA_DIFF_DB"
)

// lazyCHARun is what one helper process reports.
type lazyCHARun struct {
	Lazy      bool     // the route that ran: useLazyCHA() in the helper
	LoadError string   // the module could not be loaded; nothing else is set
	Nodes     int      // nodes of the final call graph
	Edges     []string // edges of the final call graph, sorted and unique
	Findings  []string // govulncheck findings as JSON, sorted; nil without a database
	Called    int      // findings whose trace has more than one frame
}

// TestLazyCHAHelper is not a test: it is the body of the helper process
// started by TestLazyCHADifferential, one process per route, because the
// result of either route depends on which SSA functions already exist when
// it starts, so the two must never run in one process.
func TestLazyCHAHelper(t *testing.T) {
	dir := os.Getenv(lazyCHAHelperDir)
	if dir == "" {
		t.Skip("helper process of TestLazyCHADifferential")
	}
	run := lazyCHAHelper(dir, os.Getenv(lazyCHAHelperDB))
	data, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv(lazyCHAHelperOut), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func lazyCHAHelper(dir, db string) *lazyCHARun {
	ctx := context.Background()
	run := &lazyCHARun{Lazy: useLazyCHA()}

	// The call graph, exactly as source builds it: load, buildSSA,
	// entryPoints, callGraph, nothing in between.
	graph := NewPackageGraph(runtime.Version())
	if err := graph.LoadPackagesAndMods(&packages.Config{Dir: dir}, nil, []string{"./..."}, true); err != nil {
		run.LoadError = err.Error()
		return run
	}
	if len(graph.TopPkgs()) == 0 {
		run.LoadError = "no packages"
		return run
	}
	prog, ssaPkgs := buildSSA(graph.TopPkgs(), graph.TopPkgs()[0].Fset)
	cg, err := callGraph(ctx, prog, entryPoints(ssaPkgs))
	if err != nil {
		run.LoadError = "call graph: " + err.Error()
		return run
	}
	run.Nodes = len(cg.Nodes)
	seen := make(map[string]bool)
	for f, n := range cg.Nodes {
		for _, e := range n.Out {
			pos := "-"
			if e.Site != nil {
				pos = prog.Fset.Position(e.Site.Pos()).String()
			}
			seen[fmt.Sprintf("%s @ %s -> %s", stableFuncName(f), pos, stableFuncName(e.Callee.Func))] = true
		}
	}
	for s := range seen {
		run.Edges = append(run.Edges, s)
	}
	sort.Strings(run.Edges)
	if db == "" {
		return run
	}

	// The findings, from a fresh load and a fresh SSA program, as govulncheck
	// computes them.
	c, err := client.NewClient(db, nil)
	if err != nil {
		run.LoadError = "client: " + err.Error()
		return run
	}
	graph = NewPackageGraph(runtime.Version())
	if err := graph.LoadPackagesAndMods(&packages.Config{Dir: dir}, nil, []string{"./..."}, true); err != nil {
		run.LoadError = err.Error()
		return run
	}
	h := test.NewMockHandler()
	if err := Source(ctx, h, &govulncheck.Config{ScanLevel: govulncheck.ScanLevelSymbol}, c, graph); err != nil {
		run.LoadError = "source: " + err.Error()
		return run
	}
	run.Findings = []string{}
	for _, f := range h.FindingMessages {
		data, err := json.Marshal(f)
		if err != nil {
			panic(err)
		}
		run.Findings = append(run.Findings, string(data))
		if len(f.Trace) > 1 {
			run.Called++
		}
	}
	sort.Strings(run.Findings)
	return run
}

// stableFuncName is fn.String(), except that the type arguments of an
// instance of a generic function are printed without aliases. SSA names an
// instance after the type arguments of whichever instantiation it saw
// first (slices.SortFunc[[]os.DirEntry, ...] in one run and
// slices.SortFunc[[]io/fs.DirEntry, ...] in another, or byte and uint8).
func stableFuncName(fn *ssa.Function) string {
	if p := fn.Parent(); p != nil { // anonymous function: parent's name and $n
		name := fn.Name()
		return stableFuncName(p) + name[strings.LastIndex(name, "$"):]
	}
	if o := fn.Origin(); o != nil && len(fn.TypeArgs()) > 0 {
		args := make([]string, len(fn.TypeArgs()))
		for i, t := range fn.TypeArgs() {
			args[i] = stableTypeString(t)
		}
		return o.String() + "[" + strings.Join(args, ", ") + "]"
	}
	return fn.String()
}

// stableTypeString is types.TypeString(t, nil) with aliases resolved, for
// the types that occur as type arguments in practice; other composite types
// fall back to types.TypeString.
func stableTypeString(t types.Type) string {
	switch t := types.Unalias(t).(type) {
	case *types.Basic:
		return types.Typ[t.Kind()].Name() // byte is uint8, rune is int32
	case *types.Pointer:
		return "*" + stableTypeString(t.Elem())
	case *types.Slice:
		return "[]" + stableTypeString(t.Elem())
	case *types.Array:
		return fmt.Sprintf("[%d]%s", t.Len(), stableTypeString(t.Elem()))
	case *types.Map:
		return "map[" + stableTypeString(t.Key()) + "]" + stableTypeString(t.Elem())
	case *types.Chan:
		return fmt.Sprintf("chan(%d) %s", t.Dir(), stableTypeString(t.Elem()))
	case *types.Named:
		name := t.Obj().Name()
		if pkg := t.Obj().Pkg(); pkg != nil {
			name = pkg.Path() + "." + name
		}
		if targs := t.TypeArgs(); targs.Len() > 0 {
			args := make([]string, targs.Len())
			for i := range targs.Len() {
				args[i] = stableTypeString(targs.At(i))
			}
			name += "[" + strings.Join(args, ", ") + "]"
		}
		return name
	default:
		return types.TypeString(t, nil)
	}
}

// runLazyCHAHelper runs TestLazyCHAHelper in a process of its own with the
// given route.
func runLazyCHAHelper(t *testing.T, dir, db string, lazy bool) *lazyCHARun {
	t.Helper()
	out := filepath.Join(t.TempDir(), "run.json")
	cmd := exec.Command(os.Args[0], "-test.run=^TestLazyCHAHelper$", "-test.count=1")
	route := "0"
	if lazy {
		route = "1"
	}
	cmd.Env = append(os.Environ(),
		lazyCHAEnv+"="+route,
		lazyCHAHelperDir+"="+dir,
		lazyCHAHelperDB+"="+db,
		lazyCHAHelperOut+"="+out,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper (lazy=%v) on %s: %v\n%s", lazy, dir, err, output)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var run lazyCHARun
	if err := json.Unmarshal(data, &run); err != nil {
		t.Fatal(err)
	}
	if run.Lazy != lazy {
		t.Fatalf("helper ran lazy=%v, want %v: %s is not honoured", run.Lazy, lazy, lazyCHAEnv)
	}
	return &run
}

// TestLazyCHADifferential runs each route of callGraph in processes of its
// own on the test modules of cmd/govulncheck (with their test databases)
// and on the modules in GOVULNCHECK_LAZY_CHA_DIFF_DIRS, and compares the
// final call graphs and the findings.
//
// The upstream route runs twice, to tell the noise of today's code (names
// of generic instances vary between runs) from a real difference. An edge
// that both upstream runs have and the lazy run lacks is an error; edges
// only the lazy run has are logged, as the lazy route may resolve calls
// in functions the CHA graph gives no edges (see callGraph). Any change in
// the findings outside the noise is an error.
func TestLazyCHADifferential(t *testing.T) {
	if testing.Short() {
		t.Skip("loads whole modules, in several processes")
	}
	type module struct{ dir, db string }
	var modules []module
	testdata, err := filepath.Abs(filepath.Join("..", "..", "cmd", "govulncheck", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := filepath.Glob(filepath.Join(testdata, "*", "modules", "*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range dirs {
		db, err := web.URLFromFilePath(filepath.Join(filepath.Dir(filepath.Dir(dir)), "vulndb-v1"))
		if err != nil {
			t.Fatal(err)
		}
		modules = append(modules, module{dir, db.String()})
	}
	if extra := os.Getenv(lazyCHAExtraDirs); extra != "" {
		for _, dir := range filepath.SplitList(extra) {
			modules = append(modules, module{dir, os.Getenv(lazyCHAExtraDB)})
		}
	}

	var ran, ranWithDB, loadSkips, totalEdges, totalCalled int
	for _, m := range modules {
		name := "extra_" + filepath.Base(m.dir)
		if rel, err := filepath.Rel(testdata, m.dir); err == nil && !strings.HasPrefix(rel, "..") {
			name = strings.ReplaceAll(rel, string(filepath.Separator), "_")
		}
		t.Run(name, func(t *testing.T) {
			old1 := runLazyCHAHelper(t, m.dir, m.db, false)
			if old1.LoadError != "" {
				loadSkips++
				t.Skipf("not analysed: %s", old1.LoadError)
			}
			old2 := runLazyCHAHelper(t, m.dir, m.db, false)
			lazy := runLazyCHAHelper(t, m.dir, m.db, true)
			if lazy.LoadError != "" {
				t.Fatalf("lazy route failed where the upstream route did not: %s", lazy.LoadError)
			}

			noiseEdges := symDiff(old1.Edges, old2.Edges)
			onlyOld, onlyLazy := diffLazy(old1.Edges, old2.Edges, lazy.Edges)
			t.Logf("final call graph: upstream %d nodes, %d edges; lazy %d nodes, %d edges; %d edges differ between the two upstream runs",
				old1.Nodes, len(old1.Edges), lazy.Nodes, len(lazy.Edges), len(noiseEdges))
			for _, e := range onlyOld {
				t.Errorf("edge in both upstream runs, missing from the lazy run: %s", e)
			}
			for _, e := range onlyLazy {
				t.Logf("edge only in the lazy run: %s", e)
			}

			if old1.Findings != nil {
				t.Logf("findings: upstream %d (%d called), lazy %d (%d called); %d differ between the two upstream runs",
					len(old1.Findings), old1.Called, len(lazy.Findings), lazy.Called, len(symDiff(old1.Findings, old2.Findings)))
				onlyOld, onlyLazy := diffLazy(old1.Findings, old2.Findings, lazy.Findings)
				for _, f := range onlyOld {
					t.Errorf("finding in both upstream runs, missing from the lazy run: %s", f)
				}
				for _, f := range onlyLazy {
					t.Errorf("finding only in the lazy run: %s", f)
				}
				totalCalled += old1.Called
				ranWithDB++
			}
			totalEdges += len(old1.Edges)
			ran++
		})
	}
	// Guard against comparing nothing with nothing.
	if loadSkips > 0 && ran == 0 {
		t.Errorf("no module could be loaded (%d skipped); are their dependencies in the module cache?", loadSkips)
	}
	if !t.Failed() && ((ran > 0 && totalEdges == 0) || (ranWithDB > 0 && totalCalled == 0)) {
		t.Errorf("the differential test compared too little: %d edges and %d called findings in all", totalEdges, totalCalled)
	}
}

// diffLazy returns the elements that are in both a1 and a2 but not in b,
// and those in b that are in neither a1 nor a2. All are sorted.
func diffLazy(a1, a2, b []string) (onlyA, onlyB []string) {
	in := func(s []string) map[string]bool {
		m := make(map[string]bool, len(s))
		for _, x := range s {
			m[x] = true
		}
		return m
	}
	m1, m2, mb := in(a1), in(a2), in(b)
	for _, x := range a1 {
		if m2[x] && !mb[x] {
			onlyA = append(onlyA, x)
		}
	}
	for _, x := range b {
		if !m1[x] && !m2[x] {
			onlyB = append(onlyB, x)
		}
	}
	return onlyA, onlyB
}

// symDiff returns the elements in exactly one of a and b.
func symDiff(a, b []string) []string {
	x, y := diffLazy(a, a, b)
	return append(x, y...)
}
