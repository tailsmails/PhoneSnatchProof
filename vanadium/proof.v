module vanadium

const max_proof_cases = 10_000_000

@[packed; minify]
pub struct ProofResult {
pub:
	name   string
	passed bool
	detail string
	cases  int
}

@[packed; minify]
pub struct Prover {
pub:
	name      string
	max_cases int
pub mut:
	results []ProofResult
}

@[packed; minify]
pub struct RangedIntP {
pub:
	min i64
	max i64
}

@[inline]
pub fn new_prover(name string) Prover {
	return Prover{name: name, max_cases: vanadium.max_proof_cases}
}

@[inline]
pub fn new_prover_with_limit(name string, limit int) Prover {
	return Prover{name: name, max_cases: limit}
}

@[if debug; inline]
pub fn (mut p Prover) prove_for_range(name string, min_v i64, max_v i64, prop fn (i64) bool) {
	if min_v > max_v {
		p.results << ProofResult{name: name, passed: false, detail: 'invalid range: ${min_v} > ${max_v}', cases: 0}
		return
	}
	mut cases := 0
	mut v := min_v
	for {
		cases++
		if cases > p.max_cases {
			p.results << ProofResult{name: name, passed: false, detail: 'exceeded ${p.max_cases} cases', cases: cases}
			return
		}
		if !prop(v) {
			p.results << ProofResult{name: name, passed: false, detail: 'counterexample: ${v}', cases: cases}
			return
		}
		if v == max_v {
			break
		}
		v++
	}
	p.results << ProofResult{name: name, passed: true, detail: 'proven for all ${min_v}..${max_v} (${cases} cases)', cases: cases}
}

@[if debug; inline]
pub fn (mut p Prover) prove_for_pairs(name string, min_v i64, max_v i64, prop fn (i64, i64) bool) {
	if min_v > max_v {
		p.results << ProofResult{name: name, passed: false, detail: 'invalid range', cases: 0}
		return
	}
	mut cases := 0
	mut x := min_v
	for {
		mut y := min_v
		for {
			cases++
			if cases > p.max_cases {
				p.results << ProofResult{name: name, passed: false, detail: 'exceeded case limit', cases: cases}
				return
			}
			if !prop(x, y) {
				p.results << ProofResult{name: name, passed: false, detail: 'counterexample: (${x}, ${y})', cases: cases}
				return
			}
			if y == max_v {
				break
			}
			y++
		}
		if x == max_v {
			break
		}
		x++
	}
	p.results << ProofResult{name: name, passed: true, detail: 'proven for all pairs in ${min_v}..${max_v} (${cases} cases)', cases: cases}
}

@[if debug; inline]
pub fn (mut p Prover) prove_exists(name string, min_v i64, max_v i64, prop fn (i64) bool) {
	if min_v > max_v {
		p.results << ProofResult{name: name, passed: false, detail: 'invalid range', cases: 0}
		return
	}
	mut cases := 0
	mut v := min_v
	for {
		cases++
		if cases > p.max_cases {
			p.results << ProofResult{name: name, passed: false, detail: 'no witness in ${p.max_cases} cases', cases: cases}
			return
		}
		if prop(v) {
			p.results << ProofResult{name: name, passed: true, detail: 'witness: ${v}', cases: cases}
			return
		}
		if v == max_v {
			break
		}
		v++
	}
	p.results << ProofResult{name: name, passed: false, detail: 'no witness in ${min_v}..${max_v}', cases: cases}
}

@[if debug; inline]
pub fn (mut p Prover) prove_by_samples(name string, min_v i64, max_v i64, count int, prop fn (i64) bool) {
	if count <= 0 || min_v > max_v {
		p.results << ProofResult{name: name, passed: false, detail: 'invalid parameters', cases: 0}
		return
	}
	mut cases := 0
	if !prop(min_v) {
		p.results << ProofResult{name: name, passed: false, detail: 'counterexample: ${min_v} (lower bound)', cases: 1}
		return
	}
	cases++
	if min_v != max_v {
		if !prop(max_v) {
			p.results << ProofResult{name: name, passed: false, detail: 'counterexample: ${max_v} (upper bound)', cases: 2}
			return
		}
		cases++
	}
	range_f := f64(max_v - min_v)
	samples := if count > 2 { count - 2 } else { 0 }
	for i in 0 .. samples {
		v := min_v + i64(range_f * f64(i + 1) / f64(samples + 1))
		cases++
		if !prop(v) {
			p.results << ProofResult{name: name, passed: false, detail: 'counterexample: ${v}', cases: cases}
			return
		}
	}
	p.results << ProofResult{name: name, passed: true, detail: 'passed ${cases} samples in ${min_v}..${max_v}', cases: cases}
}

@[if debug; inline]
pub fn (mut p Prover) prove_ranged(name string, r RangedIntP, prop fn (i64) bool) {
	p.prove_for_range(name, r.min, r.max, prop)
}

@[if debug; inline]
pub fn (mut p Prover) prove_commutative(name string, min_v i64, max_v i64, f fn (i64, i64) i64) {
	if min_v > max_v {
		p.results << ProofResult{name: name, passed: false, detail: 'invalid range', cases: 0}
		return
	}
	mut cases := 0
	mut x := min_v
	for {
		mut y := min_v
		for {
			cases++
			if cases > p.max_cases {
				p.results << ProofResult{name: name, passed: false, detail: 'exceeded case limit', cases: cases}
				return
			}
			if f(x, y) != f(y, x) {
				p.results << ProofResult{name: name, passed: false, detail: 'f(${x},${y})=${f(x, y)} != f(${y},${x})=${f(y, x)}', cases: cases}
				return
			}
			if y == max_v {
				break
			}
			y++
		}
		if x == max_v {
			break
		}
		x++
	}
	p.results << ProofResult{name: name, passed: true, detail: 'proven commutative for ${min_v}..${max_v} (${cases} cases)', cases: cases}
}

@[if debug; inline]
pub fn (mut p Prover) prove_associative(name string, min_v i64, max_v i64, f fn (i64, i64) i64) {
	if min_v > max_v {
		p.results << ProofResult{name: name, passed: false, detail: 'invalid range', cases: 0}
		return
	}
	mut cases := 0
	mut x := min_v
	for {
		mut y := min_v
		for {
			mut z := min_v
			for {
				cases++
				if cases > p.max_cases {
					p.results << ProofResult{name: name, passed: false, detail: 'exceeded case limit', cases: cases}
					return
				}
				lhs := f(f(x, y), z)
				rhs := f(x, f(y, z))
				if lhs != rhs {
					p.results << ProofResult{name: name, passed: false, detail: 'f(f(${x},${y}),${z})=${lhs} != f(${x},f(${y},${z}))=${rhs}', cases: cases}
					return
				}
				if z == max_v {
					break
				}
				z++
			}
			if y == max_v {
				break
			}
			y++
		}
		if x == max_v {
			break
		}
		x++
	}
	p.results << ProofResult{name: name, passed: true, detail: 'proven associative for ${min_v}..${max_v} (${cases} cases)', cases: cases}
}

@[if debug; inline]
pub fn (mut p Prover) prove_monotonic(name string, min_v i64, max_v i64, f fn (i64) i64) {
	if min_v >= max_v {
		passed := min_v == max_v
		detail := if passed { 'trivially monotonic (single value)' } else { 'invalid range' }
		p.results << ProofResult{name: name, passed: passed, detail: detail, cases: if passed { 1 } else { 0 }}
		return
	}
	mut cases := 0
	mut prev_v := min_v
	mut prev_fv := f(min_v)
	mut v := min_v
	for {
		if v == max_v {
			break
		}
		v++
		cases++
		if cases > p.max_cases {
			p.results << ProofResult{name: name, passed: false, detail: 'exceeded case limit', cases: cases}
			return
		}
		curr_fv := f(v)
		if curr_fv < prev_fv {
			p.results << ProofResult{name: name, passed: false, detail: 'f(${v})=${curr_fv} < f(${prev_v})=${prev_fv}', cases: cases}
			return
		}
		prev_v = v
		prev_fv = curr_fv
	}
	p.results << ProofResult{name: name, passed: true, detail: 'proven monotonic for ${min_v}..${max_v} (${cases} cases)', cases: cases}
}

@[if debug; inline]
pub fn (mut p Prover) prove_idempotent(name string, min_v i64, max_v i64, f fn (i64) i64) {
	if min_v > max_v {
		p.results << ProofResult{name: name, passed: false, detail: 'invalid range', cases: 0}
		return
	}
	mut cases := 0
	mut v := min_v
	for {
		cases++
		if cases > p.max_cases {
			p.results << ProofResult{name: name, passed: false, detail: 'exceeded case limit', cases: cases}
			return
		}
		fv := f(v)
		ffv := f(fv)
		if fv != ffv {
			p.results << ProofResult{name: name, passed: false, detail: 'f(${v})=${fv} but f(f(${v}))=${ffv}', cases: cases}
			return
		}
		if v == max_v {
			break
		}
		v++
	}
	p.results << ProofResult{name: name, passed: true, detail: 'proven idempotent for ${min_v}..${max_v} (${cases} cases)', cases: cases}
}

@[if debug; inline]
pub fn (mut p Prover) prove_involution(name string, min_v i64, max_v i64, f fn (i64) i64) {
	if min_v > max_v {
		p.results << ProofResult{name: name, passed: false, detail: 'invalid range', cases: 0}
		return
	}
	mut cases := 0
	mut v := min_v
	for {
		cases++
		if cases > p.max_cases {
			p.results << ProofResult{name: name, passed: false, detail: 'exceeded case limit', cases: cases}
			return
		}
		ffv := f(f(v))
		if ffv != v {
			p.results << ProofResult{name: name, passed: false, detail: 'f(f(${v}))=${ffv} != ${v}', cases: cases}
			return
		}
		if v == max_v {
			break
		}
		v++
	}
	p.results << ProofResult{name: name, passed: true, detail: 'proven involution for ${min_v}..${max_v} (${cases} cases)', cases: cases}
}

@[if debug; inline]
pub fn (mut p Prover) prove_injective(name string, min_v i64, max_v i64, f fn (i64) i64) {
	if min_v > max_v {
		p.results << ProofResult{name: name, passed: false, detail: 'invalid range', cases: 0}
		return
	}
	mut cases := 0
	mut x := min_v
	for x < max_v {
		mut y := x + 1
		for {
			cases++
			if cases > p.max_cases {
				p.results << ProofResult{name: name, passed: false, detail: 'exceeded case limit', cases: cases}
				return
			}
			if f(x) == f(y) {
				p.results << ProofResult{name: name, passed: false, detail: 'f(${x}) == f(${y}) == ${f(x)} but ${x} != ${y}', cases: cases}
				return
			}
			if y == max_v {
				break
			}
			y++
		}
		x++
	}
	p.results << ProofResult{name: name, passed: true, detail: 'proven injective for ${min_v}..${max_v} (${cases} cases)', cases: cases}
}

@[inline]
pub fn (p Prover) all_passed() bool {
	$if debug {
		if p.results.len == 0 {
			return false
		}
		for r in p.results {
			if !r.passed {
				return false
			}
		}
	}
	return true
}

@[inline]
pub fn (p Prover) passed_count() int {
	$if debug {
		mut c := 0
		for r in p.results {
			if r.passed {
				c++
			}
		}
		return c
	}
	return 0
}

@[inline]
pub fn (p Prover) failed_count() int {
	$if debug {
		mut c := 0
		for r in p.results {
			if !r.passed {
				c++
			}
		}
		return c
	}
	return 0
}

@[inline]
pub fn (p Prover) report() string {
	$if debug {
		mut lines := []string{}
		lines << '=== Proof Report: ${p.name} ==='
		lines << ''
		for r in p.results {
			status := if r.passed { 'PROVEN' } else { 'FAILED' }
			lines << '  [${status}] ${r.name}'
			lines << '           ${r.detail}'
			lines << '           (${r.cases} cases checked)'
			lines << ''
		}
		total := p.results.len
		passed := p.passed_count()
		failed := p.failed_count()
		lines << '--- Summary: ${passed}/${total} proven, ${failed} failed ---'
		return lines.join('\n')
	}
	return ''
}

@[packed; minify]
pub struct LoopProof {
pub:
	name string
pub mut:
	iteration_count    int
	invariants_checked int
	errors             []string
mut:
	prev_variant        i64
	variant_initialized bool
}

@[inline]
pub fn new_loop_proof(name string) LoopProof {
	return LoopProof{name: name}
}

@[if debug]
pub fn (mut lp LoopProof) iteration() {
	lp.iteration_count++
}

@[inline]
pub fn (mut lp LoopProof) check_invariant(condition bool, msg string) ! {
	$if debug {
		lp.invariants_checked++
		if !condition {
			detail := 'loop "${lp.name}" iteration ${lp.iteration_count}: invariant violated: ${msg}'
			lp.errors << detail
			return error(detail)
		}
	}
}

@[inline]
pub fn (mut lp LoopProof) check_variant(current i64) ! {
	$if debug {
		if lp.variant_initialized {
			if current >= lp.prev_variant {
				detail := 'loop "${lp.name}" iteration ${lp.iteration_count}: variant not decreasing: ${lp.prev_variant} -> ${current}'
				lp.errors << detail
				return error(detail)
			}
		}
		if current < 0 {
			detail := 'loop "${lp.name}" iteration ${lp.iteration_count}: variant negative: ${current}'
			lp.errors << detail
			return error(detail)
		}
		lp.prev_variant = current
		lp.variant_initialized = true
	}
}

@[inline]
pub fn (lp LoopProof) finish() ProofResult {
	$if debug {
		if lp.errors.len > 0 {
			return ProofResult{
				name:   'loop:${lp.name}'
				passed: false
				detail: lp.errors.join('; ')
				cases:  lp.iteration_count
			}
		}
		return ProofResult{
			name:   'loop:${lp.name}'
			passed: true
			detail: '${lp.iteration_count} iterations, ${lp.invariants_checked} invariant checks'
			cases:  lp.iteration_count
		}
	}
	return ProofResult{name: 'loop:${lp.name}', passed: true, detail: 'release', cases: 0}
}

@[packed; minify]
pub struct Transition {
pub:
	from int
	to   int
}

@[packed; minify]
pub struct StateMachine {
pub:
	name string
pub mut:
	current int
	trace   []int
mut:
	states      map[int]string
	transitions []Transition
}

@[inline]
pub fn new_state_machine(name string, initial int) StateMachine {
	return StateMachine{
		name:    name
		current: initial
		trace:   [initial]
	}
}

@[inline]
pub fn (mut sm StateMachine) add_state(id int, label string) {
	sm.states[id] = label
}

@[inline]
pub fn (mut sm StateMachine) add_transition(from int, to int) {
	sm.transitions << Transition{from: from, to: to}
}

@[inline]
pub fn (sm StateMachine) state_name(id int) string {
	if id in sm.states {
		return sm.states[id]
	}
	return '${id}'
}

@[inline]
fn (sm StateMachine) is_valid_transition(from int, to int) bool {
	for t in sm.transitions {
		if t.from == from && t.to == to {
			return true
		}
	}
	return false
}

@[inline]
pub fn (mut sm StateMachine) step(to int) ! {
	if !sm.is_valid_transition(sm.current, to) {
		return error('invalid transition: ${sm.state_name(sm.current)} -> ${sm.state_name(to)}')
	}
	sm.current = to
	sm.trace << to
}

@[inline]
pub fn (sm StateMachine) verify_no_deadlock() ! {
	$if debug {
		for id, label in sm.states {
			mut has_out := false
			for t in sm.transitions {
				if t.from == id {
					has_out = true
					break
				}
			}
			if !has_out {
				return error('deadlock: state ${label}(${id}) has no outgoing transitions')
			}
		}
	}
}

@[inline]
pub fn (sm StateMachine) verify_reachable(target int) bool {
	$if debug {
		mut visited := map[int]bool{}
		mut queue := [sm.trace[0]]
		visited[sm.trace[0]] = true
		for queue.len > 0 {
			current := queue[0]
			queue.delete(0)
			if current == target {
				return true
			}
			for t in sm.transitions {
				if t.from == current && !(t.to in visited) {
					visited[t.to] = true
					queue << t.to
				}
			}
		}
		return false
	}
	return true
}

@[inline]
pub fn (sm StateMachine) verify_trace(expected []int) ! {
	$if debug {
		if sm.trace.len != expected.len {
			return error('trace mismatch: expected ${expected.len} steps, got ${sm.trace.len}')
		}
		for i, s in sm.trace {
			if s != expected[i] {
				return error('trace mismatch at step ${i}: expected ${expected[i]}, got ${s}')
			}
		}
	}
}

@[inline]
pub fn guard(condition bool, msg string) ! {
	if !condition {
		return error('guard failed: ${msg}')
	}
}

@[inline]
pub fn guard_not_null[T](val ?T, msg string) !T {
	return val or { error('guard_not_null: ${msg}') }
}

@[inline]
pub fn ensure_positive(v i64) !i64 {
	if v <= 0 {
		return error('expected positive, got ${v}')
	}
	return v
}

@[inline]
pub fn ensure_non_negative(v i64) !i64 {
	if v < 0 {
		return error('expected non-negative, got ${v}')
	}
	return v
}

@[inline]
pub fn ensure_in_range(v i64, min_v i64, max_v i64) !i64 {
	if v < min_v || v > max_v {
		return error('${v} out of range [${min_v}, ${max_v}]')
	}
	return v
}

@[inline]
pub fn clamp(v i64, min_v i64, max_v i64) i64 {
	if v < min_v {
		return min_v
	}
	if v > max_v {
		return max_v
	}
	return v
}

@[inline]
pub fn in_range(v i64, min_v i64, max_v i64) bool {
	return v >= min_v && v <= max_v
}

@[inline]
pub fn safe_cast_u8(v i64) !u8 {
	if v < 0 || v > 255 {
		return error('${v} out of u8 range [0, 255]')
	}
	return u8(v)
}

@[inline]
pub fn safe_cast_i16(v i64) !i16 {
	if v < -32768 || v > 32767 {
		return error('${v} out of i16 range')
	}
	return i16(v)
}

@[inline]
pub fn safe_cast_i32(v i64) !i32 {
	if v < -2147483648 || v > 2147483647 {
		return error('${v} out of i32 range')
	}
	return i32(v)
}