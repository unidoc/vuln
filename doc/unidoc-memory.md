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

## A larger corpus (26 November 2026)

`TestLazyCHADifferential` on 25 popular Go modules and minio, with a frozen copy of vuln.go.dev's database (modified
2026-11-26) so that every run saw the same entries: BurntSushi/toml, cespare/xxhash, fatih/color, gin-gonic/gin, go-chi/chi,
go-yaml/yaml, gofrs/uuid, golang-jwt/jwt, google/go-cmp, google/uuid, gorilla/mux, hashicorp/go-multierror, joho/godotenv,
kelseyhightower/envconfig, mattn/go-isatty, mitchellh/mapstructure, rs/zerolog, sirupsen/logrus, spf13/cobra, spf13/pflag,
stretchr/testify and urfave/cli at fixed commits, and minio at 7aac2a2. davecgh/go-spew, pkg/errors and pmezard/go-difflib
had no go.mod at their commits and did not load.

- **Identical call graphs and findings on all 22 modules,** from 2,110 nodes and 8,475 edges (go-isatty) to 20,852 and
  122,592 (gin, 67 findings, 52 called). The two upstream runs agreed with each other everywhere.
- **minio: identical findings** (591, 451 called; the same traces), and 4 edges only in the lazy graph out of 529,578. All
  four are the superset case above: `MakeVolHandler` and `MakeVolBulkHandler` of `cmd.storageRESTServer` are never
  referenced, and their interface calls `s.getStorage().MakeVol` and `.MakeVolBulk` have no callee in upstream's graph.
  The lazy route resolves them to `storageRESTClient` and `xlStorageDiskIDCheck`, the two implementations. No finding moved.

Memory and time on minio, on a Mac (Apple silicon, 10 cores, Go 1.27.3), three interleaved rounds of each build, from
`GODEBUG=gctrace=1` (the largest heap at a GC's start, and the largest live heap after one; macOS's peak RSS excludes
compressed pages and is not comparable). The median of the three:

| Build | Peak heap | Peak live heap | Time (with gctrace) | Time (without) |
|---|---|---|---|---|
| v1.9.0 (x/tools v0.52.0) | 5,442 MB | 3,629 MB | 28 s | 25.6 s |
| master (v1.10.0 and the source fix) | 5,294 MB | 3,588 MB | 26 s | 15.5 s |
| `TypesInfo` drop | 4,448 MB (-16%) | 3,001 MB (-16%) | 25 s | 14.7 s |
| both, `GOVULNCHECK_LAZY_CHA=1` | 4,482 MB (-15%) | 2,615 MB (-27%) | 15 s | 11.5 s (-26%) |

The peak heap at a GC's start depends on when the collector runs and varies by several hundred MB between rounds; the live
heap is the steadier measure, and it is what a memory limit (`GOMEMLIMIT`) has to fit above. The findings were the same in
every run of every build.

## Before turning the lazy route on by default

The larger corpus found no difference in findings and only the expected superset edges. What is left is to decide whether a
finding that moves from imported to called through such an edge is acceptable (it would be a call upstream misses), and
to offer both changes upstream (the second finishes golang/go#57357).
