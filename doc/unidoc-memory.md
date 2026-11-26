# UniDoc fork: memory and speed changes to the symbol scan

Two changes to `internal/vulncheck` that lower the memory and time of govulncheck's symbol scan (`-scan symbol`, the
default) on large programs. They come from profiling a symbol scan of minio (26 November 2026).

## Why the scan needs so much memory

The symbol scan loads every package of the build from source (minio: 1318 packages, 7517 files), builds SSA for every
function, then builds a CHA call graph of the whole program, slices it from the entry points and runs VTA twice. On minio
the live heap at the high point is about 3.5 GB: SSA 0.9 GB, the `types.Info` maps 0.8 GB, syntax 0.6 GB, `go/types`
objects 0.26 GB, and the CHA graph with 13.46 million edges 0.64 GB. With GOGC=100 the process peaks at about 6.7 GB.

## Change 1: drop `TypesInfo` after the SSA build (always on)

Branch `drop-typesinfo`. After `prog.Build()`, `buildSSA` sets `TypesInfo` to nil on every loaded package. Nothing in
govulncheck reads it afterwards, and SSA keeps its own pointer to the `types.Info` of the functions that still need it
(generic functions, for instances built later). The `PackageGraph` holds the packages to the end of the scan, so without
this the maps stay alive through the call graph phase, where the peak is.

Syntax stays: SSA functions keep their syntax (`DeleteSyntheticNodes` reads `Function.Syntax()`), and the witness code reads
package syntax for init positions.

Measured on minio (x/vuln v1.9.0 with the same patch): the live heap after SSA falls by 625 MB, the scan's peak
by about 1.1 GB (6.7 to 5.6 GB, **-17%**), with identical findings and call stacks. No measurable change in time.

## Change 2: no explicit CHA graph (opt in, `GOVULNCHECK_LAZY_CHA=1`)

Branch `lazy-cha`. With the environment variable set to `1`, `callGraph` does not call `cha.CallGraph`. It takes
`ssautil.AllFunctions(prog)` at the same point, computes the first forward slice by asking `chautil.LazyCallees` (the
function `cha.CallGraph` makes its edges with) for the callees of each call site, and calls `vta.CallGraph(slice, nil)`,
which uses the same lazy CHA internally. The second slice and VTA round are unchanged. Without the variable the upstream
route runs, unchanged.

- `internal/chautil/lazy.go` is a copy of x/tools v0.53.0's `go/callgraph/internal/chautil/lazy.go` (internal to x/tools,
  so x/vuln cannot import it). Keep it in step with the x/tools version in go.mod.
- The function list must be taken where `cha.CallGraph` takes it today: SSA creates some functions on demand, so the list
  depends on what ran before.
- As in the CHA graph, the slice resolves call sites only of functions in that list, so the slice is the same.
- VTA's starting callees are the same whenever every slice function is in the list. When one is not (a function reached
  only as a static callee or a method value), the CHA graph gives it no outgoing edges, so its interface calls resolve to
  nothing today, while the lazy route resolves them. The lazy graph is then a superset: it can add edges, never remove one,
  so a finding can move from imported to called, never the other way.

Measured on minio (both changes together, x/vuln v1.9.0, x/tools v0.52.0, three interleaved runs): peak about
6.7 to 5.1 GB (**-25%**), live heap about 3.6 to 2.75 GB, scan wall and CPU time about **-25%**, findings identical (43
called, 54 imported, the same 314 call stacks). The final call graph had 4 more edges than upstream's 528,028, at two
interface calls in minio's `cmd/storage-rest-server.go` where upstream finds no callee at all. That is consistent with the superset case above, but not yet confirmed.

That measurement used a slightly different slice (it resolved call sites of every slice function, not only of listed ones) and was
not repeated with this implementation; the numbers are expected to carry over but have not been re-measured.

## The differential test

`internal/vulncheck/lazycha_test.go`, `TestLazyCHADifferential` (skipped with `-short`). For each test module of
`cmd/govulncheck/testdata` (with its test database) it runs the upstream route twice and the lazy route once, each in a
process of its own (the test binary re-executed as `TestLazyCHAHelper`), and compares the final call graph edges (caller,
call site position, callee; generic instance names printed without aliases) and the findings. An edge in both upstream
runs but not in the lazy run, or any change in the findings, fails the test (findings are compared as govulncheck
writes them, so on a larger corpus the run-to-run naming of generic instances in call stacks, such as `byte` or `uint8`,
can show up as a false difference); edges only in the lazy run are logged. More
modules can be added with `GOVULNCHECK_LAZY_CHA_DIFF_DIRS` (path list) and `GOVULNCHECK_LAZY_CHA_DIFF_DB` (database URL;
without it only call graphs are compared):

```
GOVULNCHECK_LAZY_CHA_DIFF_DIRS=/path/to/mod1:/path/to/mod2 \
  go test -run 'TestLazyCHADifferential/extra' -v ./internal/vulncheck/
```

Results on 26 November 2026 (Mac, Go 1.27.3): identical call graphs and findings on the 10 test modules that load (the
`nogomod` module, which has no go.mod, fails to load and is skipped), and identical call graphs on three larger programs:
this repository (13,035 nodes, 66,102 edges), unipdf (20,006 / 98,998) and goja
(10,127 / 99,388). No difference was observed, so if any slice function there is outside the function list, it changed no edge (that number
was not counted).

## Before turning the lazy route on by default

Run the differential test on a corpus of large programs (the replay's repositories and minio) with a frozen database,
and decide what to do if a finding changes from imported to called. Both changes are worth offering upstream (the second
finishes golang/go#57357).
