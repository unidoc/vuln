// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// forwardSlice computes the transitive closure of functions forward reachable
// via calls in cg or referred to in an instruction starting from `sources`.
func forwardSlice(sources map[*ssa.Function]bool, cg *callgraph.Graph) map[*ssa.Function]bool {
	seen := make(map[*ssa.Function]bool)
	var visit func(f *ssa.Function)
	visit = func(f *ssa.Function) {
		if seen[f] {
			return
		}
		seen[f] = true

		if n := cg.Nodes[f]; n != nil {
			for _, e := range n.Out {
				if e.Site != nil {
					visit(e.Callee.Func)
				}
			}
		}

		var buf [10]*ssa.Value // avoid alloc in common case
		for _, b := range f.Blocks {
			for _, instr := range b.Instrs {
				for _, op := range instr.Operands(buf[:0]) {
					if fn, ok := (*op).(*ssa.Function); ok {
						visit(fn)
					}
				}
			}
		}
	}
	for source := range sources {
		visit(source)
	}
	return seen
}

// lazyForwardSlice computes the same slice as forwardSlice does on the CHA
// call graph of the functions in allFuncs (cha.CallGraph), without building
// that graph: the callees of a call site come from callees, the function
// cha.CallGraph makes its edges with. As in that graph, only the call sites
// of functions in allFuncs are resolved; a function outside allFuncs has no
// outgoing edges there, and here only its operands are followed.
func lazyForwardSlice(sources, allFuncs map[*ssa.Function]bool, callees func(ssa.CallInstruction) []*ssa.Function) map[*ssa.Function]bool {
	seen := make(map[*ssa.Function]bool)
	var visit func(f *ssa.Function)
	visit = func(f *ssa.Function) {
		if seen[f] {
			return
		}
		seen[f] = true

		resolve := allFuncs[f]
		var buf [10]*ssa.Value // avoid alloc in common case
		for _, b := range f.Blocks {
			for _, instr := range b.Instrs {
				if site, ok := instr.(ssa.CallInstruction); ok && resolve {
					if g := site.Common().StaticCallee(); g != nil {
						visit(g)
					} else {
						for _, g := range callees(site) {
							visit(g)
						}
					}
				}
				for _, op := range instr.Operands(buf[:0]) {
					if fn, ok := (*op).(*ssa.Function); ok {
						visit(fn)
					}
				}
			}
		}
	}
	for source := range sources {
		visit(source)
	}
	return seen
}
