module vanadium

import math
import sync

@[packed; minify]
pub struct StrongI64 {
pub:
	tag string
	val i64
}

@[inline; _hot]
pub fn new_strong_i64(tag string, val i64) StrongI64 {
	return StrongI64{ tag: tag, val: val }
}

@[inline; _hot]
pub fn new_strong_ranged_i64(tag string, val i64, min_v i64, max_v i64) !StrongI64 {
	if _unlikely_(val < min_v || val > max_v) {
		return error('Constraint_Error: ${val} not in ${min_v}..${max_v} [${tag}]')
	}
	return StrongI64{ tag: tag, val: val }
}

@[inline; _hot]
fn (a StrongI64) type_check(b StrongI64, op string) ! {
	if _unlikely_(a.tag != b.tag) {
		return error('Type_Error: cannot ${op} "${a.tag}" and "${b.tag}"')
	}
}

@[inline; _hot]
pub fn (a StrongI64) add(b StrongI64) !StrongI64 {
	a.type_check(b, 'add')!
	return StrongI64{ tag: a.tag, val: safe_add_i64(a.val, b.val)! }
}

@[inline; _hot]
pub fn (a StrongI64) sub(b StrongI64) !StrongI64 {
	a.type_check(b, 'subtract')!
	return StrongI64{ tag: a.tag, val: safe_sub_i64(a.val, b.val)! }
}

@[inline; _hot]
pub fn (a StrongI64) mul(b StrongI64) !StrongI64 {
	a.type_check(b, 'multiply')!
	return StrongI64{ tag: a.tag, val: safe_mul_i64(a.val, b.val)! }
}

@[inline; _hot]
pub fn (a StrongI64) div(b StrongI64) !StrongI64 {
	a.type_check(b, 'divide')!
	return StrongI64{ tag: a.tag, val: safe_div_i64(a.val, b.val)! }
}

@[inline; _hot]
pub fn (a StrongI64) cmp(b StrongI64) !int {
	a.type_check(b, 'compare')!
	if a.val < b.val {
		return -1
	}
	if a.val > b.val {
		return 1
	}
	return 0
}

@[inline; _hot]
pub fn (a StrongI64) eq(b StrongI64) !bool {
	a.type_check(b, 'compare')!
	return a.val == b.val
}

@[inline; _hot]
pub fn (s StrongI64) raw() i64 {
	return s.val
}

@[inline; _hot]
pub fn (s StrongI64) convert(new_tag string) StrongI64 {
	return StrongI64{ tag: new_tag, val: s.val }
}

@[inline; _hot]
pub fn (s StrongI64) str() string {
	return '${s.val} [${s.tag}]'
}

@[inline; _hot]
pub fn strong_div_i64(a StrongI64, b StrongI64, result_tag string) !StrongI64 {
	return StrongI64{ tag: result_tag, val: safe_div_i64(a.val, b.val)! }
}

@[inline; _hot]
pub fn strong_mul_i64(a StrongI64, b StrongI64, result_tag string) !StrongI64 {
	return StrongI64{ tag: result_tag, val: safe_mul_i64(a.val, b.val)! }
}

@[packed; minify]
pub struct StrongF64 {
pub:
	tag string
	val f64
}

@[inline; _hot]
fn check_float(result f64) ! {
	if _unlikely_(math.is_nan(result)) {
		return error('Arithmetic_Error: NaN result')
	}
	if _unlikely_(math.is_inf(result, 0)) {
		return error('Overflow_Error: infinite result')
	}
}

@[inline; _hot]
pub fn new_strong_f64(tag string, val f64) !StrongF64 {
	check_float(val)!
	return StrongF64{ tag: tag, val: val }
}

@[inline; _hot]
fn (a StrongF64) type_check(b StrongF64, op string) ! {
	if _unlikely_(a.tag != b.tag) {
		return error('Type_Error: cannot ${op} "${a.tag}" and "${b.tag}"')
	}
}

@[inline; _hot]
pub fn (a StrongF64) add(b StrongF64) !StrongF64 {
	a.type_check(b, 'add')!
	result := a.val + b.val
	check_float(result)!
	return StrongF64{ tag: a.tag, val: result }
}

@[inline; _hot]
pub fn (a StrongF64) sub(b StrongF64) !StrongF64 {
	a.type_check(b, 'subtract')!
	result := a.val - b.val
	check_float(result)!
	return StrongF64{ tag: a.tag, val: result }
}

@[inline; _hot]
pub fn (a StrongF64) mul(b StrongF64) !StrongF64 {
	a.type_check(b, 'multiply')!
	result := a.val * b.val
	check_float(result)!
	return StrongF64{ tag: a.tag, val: result }
}

@[inline; _hot]
pub fn (a StrongF64) div(b StrongF64) !StrongF64 {
	a.type_check(b, 'divide')!
	if _unlikely_(b.val == 0.0) {
		return error('Division_Error: division by zero')
	}
	result := a.val / b.val
	check_float(result)!
	return StrongF64{ tag: a.tag, val: result }
}

@[inline; _hot]
pub fn (a StrongF64) eq(b StrongF64) !bool {
	a.type_check(b, 'compare')!
	return a.val == b.val
}

@[inline; _hot]
pub fn (s StrongF64) raw() f64 {
	return s.val
}

@[inline; _hot]
pub fn (s StrongF64) convert(new_tag string) StrongF64 {
	return StrongF64{ tag: new_tag, val: s.val }
}

@[inline; _hot]
pub fn (s StrongF64) str() string {
	return '${s.val} [${s.tag}]'
}

@[inline; _hot]
pub fn strong_div_f64(a StrongF64, b StrongF64, result_tag string) !StrongF64 {
	if _unlikely_(b.val == 0.0) {
		return error('Division_Error: division by zero')
	}
	result := a.val / b.val
	check_float(result)!
	return StrongF64{ tag: result_tag, val: result }
}

@[inline; _hot]
pub fn strong_mul_f64(a StrongF64, b StrongF64, result_tag string) !StrongF64 {
	result := a.val * b.val
	check_float(result)!
	return StrongF64{ tag: result_tag, val: result }
}

@[packed; minify]
pub struct SecureBuffer {
pub:
	capacity int
mut:
	data    []u8
	cleared bool
	mtx     &sync.RwMutex = sync.new_rwmutex()
}

@[inline; _hot]
pub fn new_secure_buffer(capacity int) !SecureBuffer {
	if _unlikely_(capacity <= 0) {
		return error('Capacity_Error: must be > 0')
	}
	return SecureBuffer{ capacity: capacity, data: []u8{cap: capacity} }
}

@[inline; _hot]
pub fn (mut sb SecureBuffer) write(bytes []u8) ! {
	sb.mtx.lock()
	defer { sb.mtx.unlock() }
	if _unlikely_(sb.data.len + bytes.len > sb.capacity) {
		return error('Capacity_Error: need ${bytes.len}, ${sb.capacity - sb.data.len} available')
	}
	for b in bytes {
		sb.data << b
	}
}

@[inline; _hot]
pub fn (mut sb SecureBuffer) write_byte(b u8) ! {
	sb.mtx.lock()
	defer { sb.mtx.unlock() }
	if _unlikely_(sb.data.len >= sb.capacity) {
		return error('Capacity_Error: buffer full')
	}
	sb.data << b
}

@[inline; _hot]
pub fn (mut sb SecureBuffer) read() ![]u8 {
	sb.mtx.rlock()
	defer { sb.mtx.runlock() }
	if _unlikely_(sb.data.len == 0) {
		return error('Empty_Error: buffer empty')
	}
	return sb.data.clone()
}

@[inline; _hot]
pub fn (mut sb SecureBuffer) at(index int) !u8 {
	sb.mtx.rlock()
	defer { sb.mtx.runlock() }
	if _unlikely_(index < 0 || index >= sb.data.len) {
		return error('Index_Error: ${index} out of bounds 0..${sb.data.len - 1}')
	}
	return sb.data[index]
}

@[inline; _hot]
pub fn (mut sb SecureBuffer) len() int {
	sb.mtx.rlock()
	defer { sb.mtx.runlock() }
	return sb.data.len
}

@[inline; _hot]
pub fn (mut sb SecureBuffer) clear() {
	sb.mtx.lock()
	defer { sb.mtx.unlock() }
	n := sb.data.len
	for i in 0 .. n {
		sb.data[i] = 0x00
	}
	for i in 0 .. n {
		sb.data[i] = 0xFF
	}
	for i in 0 .. n {
		sb.data[i] = u8((i * 0x5A + 0xA5) & 0xFF)
	}
	for i in 0 .. n {
		sb.data[i] = 0x00
	}
	mut barrier := u8(0)
	for i in 0 .. n {
		barrier |= sb.data[i]
	}
	_ = barrier
	sb.data.clear()
	sb.cleared = true
}

@[inline; _hot]
pub fn (mut sb SecureBuffer) is_cleared() bool {
	sb.mtx.rlock()
	defer { sb.mtx.runlock() }
	return sb.cleared
}

const canary_head = u64(0xDEADBEEFCAFEBABE)
const canary_tail = u64(0xFEEDFACEDEADC0DE)

@[packed; minify]
pub struct GuardedI64 {
mut:
	head  u64
	val   i64
	guard i64
	tail  u64
}

@[inline; _hot]
pub fn new_guarded_i64(v i64) GuardedI64 {
	return GuardedI64{
		head:  canary_head
		val:   v
		guard: ~v
		tail:  canary_tail
	}
}

@[inline; _hot]
pub fn (g GuardedI64) get() !i64 {
	if _unlikely_(g.head != canary_head || g.tail != canary_tail) {
		return error('Memory_Corruption: canary violation (buffer overflow detected)')
	}
	if _unlikely_(g.val != ~g.guard) {
		return error('Memory_Corruption: bit-flip detected')
	}
	return g.val
}

@[inline; _hot]
pub fn (mut g GuardedI64) set(v i64) {
	g.head = canary_head
	g.val = v
	g.guard = ~v
	g.tail = canary_tail
}

@[inline; _hot]
pub fn (g GuardedI64) verify() bool {
	return g.head == canary_head && g.tail == canary_tail && g.val == ~g.guard
}

@[inline; _hot]
pub fn (g GuardedI64) str() string {
	v := g.get() or { return 'CORRUPTED' }
	return '${v} (guarded)'
}

@[packed; minify]
pub struct FlowGuard {
mut:
	steps   []string
	current int
	mtx     &sync.RwMutex = sync.new_rwmutex()
}

@[inline; _hot]
pub fn new_flow_guard(expected []string) !FlowGuard {
	if _unlikely_(expected.len == 0) {
		return error('Flow_Error: no steps defined')
	}
	return FlowGuard{ steps: expected, current: 0 }
}

@[inline; _hot]
pub fn (mut fg FlowGuard) step(name string) ! {
	fg.mtx.lock()
	defer { fg.mtx.unlock() }
	if _unlikely_(fg.current >= fg.steps.len) {
		return error('Flow_Error: unexpected step "${name}" after completion')
	}
	if _unlikely_(fg.steps[fg.current] != name) {
		return error('Flow_Error: expected "${fg.steps[fg.current]}", got "${name}"')
	}
	fg.current++
}

@[inline; _hot]
pub fn (mut fg FlowGuard) verify_complete() ! {
	fg.mtx.rlock()
	defer { fg.mtx.runlock() }
	if _unlikely_(fg.current != fg.steps.len) {
		return error('Flow_Error: ${fg.steps.len - fg.current} steps remaining, next: "${fg.steps[fg.current]}"')
	}
}

@[inline; _hot]
pub fn (mut fg FlowGuard) reset() {
	fg.mtx.lock()
	defer { fg.mtx.unlock() }
	fg.current = 0
}

@[inline; _hot]
pub fn (mut fg FlowGuard) current_step() string {
	fg.mtx.rlock()
	defer { fg.mtx.runlock() }
	if fg.current >= fg.steps.len {
		return 'complete'
	}
	return fg.steps[fg.current]
}

@[inline; _hot]
pub fn (mut fg FlowGuard) progress() string {
	fg.mtx.rlock()
	defer { fg.mtx.runlock() }
	return '${fg.current}/${fg.steps.len}'
}

@[packed; minify]
pub struct NonceTracker {
mut:
	used    map[u64]bool
	counter u64
	mtx     &sync.RwMutex = sync.new_rwmutex()
}

@[inline; _hot]
pub fn new_nonce_tracker() NonceTracker {
	return NonceTracker{ used: map[u64]bool{}, counter: 0 }
}

@[inline; _hot]
pub fn (mut nt NonceTracker) use_nonce(nonce u64) ! {
	nt.mtx.lock()
	defer { nt.mtx.unlock() }
	if _unlikely_(nonce in nt.used) {
		return error('Nonce_Error: ${nonce} already used')
	}
	nt.used[nonce] = true
}

@[inline; _hot]
pub fn (mut nt NonceTracker) next() u64 {
	nt.mtx.lock()
	defer { nt.mtx.unlock() }
	nt.counter++
	nt.used[nt.counter] = true
	return nt.counter
}

@[inline; _hot]
pub fn (mut nt NonceTracker) is_used(nonce u64) bool {
	nt.mtx.rlock()
	defer { nt.mtx.runlock() }
	return nonce in nt.used
}

@[inline; _hot]
pub fn (mut nt NonceTracker) count() int {
	nt.mtx.rlock()
	defer { nt.mtx.runlock() }
	return nt.used.len
}

@[packed; minify]
pub struct DepthGuard {
pub:
	max_depth int
mut:
	current int
	mtx     &sync.RwMutex = sync.new_rwmutex()
}

@[inline; _hot]
pub fn new_depth_guard(max_depth int) !DepthGuard {
	if _unlikely_(max_depth <= 0) {
		return error('Depth_Error: max must be > 0')
	}
	return DepthGuard{ max_depth: max_depth, current: 0 }
}

@[inline; _hot]
pub fn (mut dg DepthGuard) enter() ! {
	dg.mtx.lock()
	defer { dg.mtx.unlock() }
	if _unlikely_(dg.current >= dg.max_depth) {
		return error('Depth_Error: max depth ${dg.max_depth} exceeded')
	}
	dg.current++
}

@[inline; _hot]
pub fn (mut dg DepthGuard) leave() {
	dg.mtx.lock()
	defer { dg.mtx.unlock() }
	if dg.current > 0 {
		dg.current--
	}
}

@[inline; _hot]
pub fn (mut dg DepthGuard) depth() int {
	dg.mtx.rlock()
	defer { dg.mtx.runlock() }
	return dg.current
}

@[inline; _hot]
pub fn (mut dg DepthGuard) remaining() int {
	dg.mtx.rlock()
	defer { dg.mtx.runlock() }
	return dg.max_depth - dg.current
}

@[inline; _hot]
pub fn redundant_require(check fn () bool, msg string) ! {
	r1 := check()
	r2 := check()
	r3 := check()
	mut passed := 0
	if r1 {
		passed++
	}
	if r2 {
		passed++
	}
	if r3 {
		passed++
	}
	if _unlikely_(passed < 2) {
		return error('Precondition_Failed: ${msg}')
	}
	if _unlikely_(passed < 3) {
		return error('Fault_Detected: inconsistent results for "${msg}"')
	}
}

@[inline; _hot]
pub fn tmr_i64(f fn () i64) !i64 {
	r1 := f()
	r2 := f()
	r3 := f()
	if r1 == r2 || r1 == r3 {
		return r1
	}
	if r2 == r3 {
		return r2
	}
	return error('TMR_Error: all results differ (${r1}, ${r2}, ${r3})')
}

@[inline; _hot]
pub fn tmr_bool(f fn () bool) bool {
	mut count := 0
	if f() {
		count++
	}
	if f() {
		count++
	}
	if f() {
		count++
	}
	return count >= 2
}

@[inline; _hot]
pub fn validate_entropy(data []u8, min_unique_ratio f64) ! {
	if _unlikely_(data.len == 0) {
		return error('Entropy_Error: empty data')
	}
	mut seen := []bool{len: 256}
	mut unique := 0
	for b in data {
		if !seen[int(b)] {
			seen[int(b)] = true
			unique++
		}
	}
	max_possible := if data.len > 256 { 256 } else { data.len }
	ratio := f64(unique) / f64(max_possible)
	if _unlikely_(ratio < min_unique_ratio) {
		return error('Entropy_Error: ratio ${ratio:.3} below minimum ${min_unique_ratio:.3}')
	}
}