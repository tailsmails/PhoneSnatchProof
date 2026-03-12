module vanadium

import sync
import time

pub const max_i64_val = i64(9223372036854775807)
pub const min_i64_val = i64(-9223372036854775807 - 1)
pub const max_i32_val = i64(2147483647)
pub const min_i32_val = i64(-2147483648)

@[packed; minify]
pub struct RangedInt {
pub:
	min i64
	max i64
mut:
	val i64
}

@[inline; _hot]
pub fn (r RangedInt) in_range(v i64) bool {
	return v >= r.min && v <= r.max
}

@[inline; _hot]
pub fn RangedInt.create(min_v i64, max_v i64, initial i64) !RangedInt {
	if _unlikely_(min_v > max_v) {
		return error('Range_Error: min > max')
	}
	if _unlikely_(initial < min_v || initial > max_v) {
		return error('Constraint_Error: ${initial} not in ${min_v}..${max_v}')
	}
	return RangedInt{ min: min_v, max: max_v, val: initial }
}

@[inline; _hot]
pub fn (r RangedInt) value() i64 {
	return r.val
}

@[inline; _hot]
pub fn (mut r RangedInt) assign(v i64) ! {
	if _unlikely_(v < r.min || v > r.max) {
		return error('Constraint_Error: ${v} not in ${r.min}..${r.max}')
	}
	r.val = v
}

@[inline; _hot]
pub fn (r RangedInt) str() string {
	return '${r.val} in [${r.min}..${r.max}]'
}

@[inline; _hot]
pub fn (r RangedInt) checked_add(other i64) !RangedInt {
	if _unlikely_((other > 0 && r.val > vanadium.max_i64_val - other) || (other < 0 && r.val < vanadium.min_i64_val - other)) {
		return error('Overflow_Error: ${r.val} + ${other}')
	}
	result := r.val + other
	if _unlikely_(result < r.min || result > r.max) {
		return error('Constraint_Error: ${r.val} + ${other} = ${result} not in ${r.min}..${r.max}')
	}
	return RangedInt{ min: r.min, max: r.max, val: result }
}

@[inline; _hot]
pub fn (r RangedInt) checked_sub(other i64) !RangedInt {
	if _unlikely_((other > 0 && r.val < vanadium.min_i64_val + other) || (other < 0 && r.val > vanadium.max_i64_val + other)) {
		return error('Overflow_Error: ${r.val} - ${other}')
	}
	result := r.val - other
	if _unlikely_(result < r.min || result > r.max) {
		return error('Constraint_Error: ${r.val} - ${other} = ${result} not in ${r.min}..${r.max}')
	}
	return RangedInt{ min: r.min, max: r.max, val: result }
}

@[inline; _hot]
pub fn (r RangedInt) checked_mul(other i64) !RangedInt {
	if r.val != 0 && other != 0 {
		if _unlikely_((r.val > 0 && other > 0 && r.val > vanadium.max_i64_val / other) || (r.val < 0 && other < 0 && r.val < vanadium.max_i64_val / other) || (r.val > 0 && other < 0 && other < vanadium.min_i64_val / r.val) || (r.val < 0 && other > 0 && r.val < vanadium.min_i64_val / other)) {
			return error('Overflow_Error: ${r.val} * ${other}')
		}
	}
	result := r.val * other
	if _unlikely_(result < r.min || result > r.max) {
		return error('Constraint_Error: ${r.val} * ${other} = ${result} not in ${r.min}..${r.max}')
	}
	return RangedInt{ min: r.min, max: r.max, val: result }
}

@[inline; _hot]
pub fn (r RangedInt) checked_div(other i64) !RangedInt {
	if _unlikely_(other == 0) {
		return error('Division_Error: division by zero')
	}
	if _unlikely_(r.val == vanadium.min_i64_val && other == -1) {
		return error('Overflow_Error: ${r.val} / ${other}')
	}
	result := r.val / other
	if _unlikely_(result < r.min || result > r.max) {
		return error('Constraint_Error: ${r.val} / ${other} = ${result} not in ${r.min}..${r.max}')
	}
	return RangedInt{ min: r.min, max: r.max, val: result }
}

@[packed; minify]
pub struct SafeList[T] {
pub:
	capacity    int
	lower_bound int
mut:
	data []T
	mtx  &sync.RwMutex = sync.new_rwmutex()
}

@[inline; _hot]
pub fn new_safe_list[T](capacity int) !SafeList[T] {
	if _unlikely_(capacity <= 0) {
		return error('Capacity_Error: capacity must be > 0')
	}
	return SafeList[T]{ capacity: capacity, lower_bound: 1, data: []T{cap: capacity} }
}

@[inline; _hot]
pub fn new_bounded_list[T](capacity int, lower_bound int) !SafeList[T] {
	if _unlikely_(capacity <= 0) {
		return error('Capacity_Error: capacity must be > 0')
	}
	return SafeList[T]{ capacity: capacity, lower_bound: lower_bound, data: []T{cap: capacity} }
}

@[inline; _hot]
fn (s SafeList[T]) upper_bound_unlocked() int {
	return s.lower_bound + s.data.len - 1
}

@[inline; _hot]
pub fn (mut s SafeList[T]) upper_bound() int {
	s.mtx.rlock()
	defer { s.mtx.runlock() }
	return s.upper_bound_unlocked()
}

@[inline; _hot]
pub fn (mut s SafeList[T]) at(index int) !T {
	s.mtx.rlock()
	defer { s.mtx.runlock() }
	if _unlikely_(s.data.len == 0) {
		return error('Index_Error: list is empty')
	}
	real := index - s.lower_bound
	if _unlikely_(real < 0 || real >= s.data.len) {
		return error('Index_Error: ${index} not in ${s.lower_bound}..${s.upper_bound_unlocked()}')
	}
	return s.data[real]
}

@[inline; _hot]
pub fn (mut s SafeList[T]) set_at(index int, val T) ! {
	s.mtx.lock()
	defer { s.mtx.unlock() }
	real := index - s.lower_bound
	if _unlikely_(real < 0 || real >= s.data.len) {
		return error('Index_Error: ${index} not in ${s.lower_bound}..${s.upper_bound_unlocked()}')
	}
	s.data[real] = val
}

@[inline; _hot]
pub fn (mut s SafeList[T]) append(val T) ! {
	s.mtx.lock()
	defer { s.mtx.unlock() }
	if _unlikely_(s.data.len >= s.capacity) {
		return error('Capacity_Error: list full (max: ${s.capacity})')
	}
	s.data << val
}

@[inline; _hot]
pub fn (mut s SafeList[T]) append_many(vals []T) ! {
	s.mtx.lock()
	defer { s.mtx.unlock() }
	if _unlikely_(s.data.len + vals.len > s.capacity) {
		return error('Capacity_Error: need ${vals.len} slots, only ${s.capacity - s.data.len} available')
	}
	for v in vals {
		s.data << v
	}
}

@[inline; _hot]
pub fn (mut s SafeList[T]) remove_at(index int) !T {
	s.mtx.lock()
	defer { s.mtx.unlock() }
	real := index - s.lower_bound
	if _unlikely_(real < 0 || real >= s.data.len) {
		return error('Index_Error: ${index} not in ${s.lower_bound}..${s.upper_bound_unlocked()}')
	}
	val := s.data[real]
	s.data.delete(real)
	return val
}

@[inline; _hot]
pub fn (mut s SafeList[T]) first() !T {
	s.mtx.rlock()
	defer { s.mtx.runlock() }
	if _unlikely_(s.data.len == 0) {
		return error('Empty_Error: list is empty')
	}
	return s.data[0]
}

@[inline; _hot]
pub fn (mut s SafeList[T]) last() !T {
	s.mtx.rlock()
	defer { s.mtx.runlock() }
	if _unlikely_(s.data.len == 0) {
		return error('Empty_Error: list is empty')
	}
	return s.data[s.data.len - 1]
}

@[inline; _hot]
pub fn (mut s SafeList[T]) pop() !T {
	s.mtx.lock()
	defer { s.mtx.unlock() }
	if _unlikely_(s.data.len == 0) {
		return error('Empty_Error: cannot pop from empty list')
	}
	return s.data.pop()
}

@[inline; _hot]
pub fn (mut s SafeList[T]) safe_slice(from int, to int) !SafeList[T] {
	s.mtx.rlock()
	defer { s.mtx.runlock() }
	if _unlikely_(from > to) {
		return error('Range_Error: from > to')
	}
	real_from := from - s.lower_bound
	real_to := to - s.lower_bound
	if _unlikely_(real_from < 0 || real_to >= s.data.len) {
		return error('Index_Error: slice [${from}..${to}] out of bounds')
	}
	mut result := new_bounded_list[T](real_to - real_from + 1, from)!
	for i in real_from .. real_to + 1 {
		result.data << s.data[i]
	}
	return result
}

@[inline; _hot]
pub fn (mut s SafeList[T]) each(callback fn (int, T)) {
	s.mtx.rlock()
	defer { s.mtx.runlock() }
	for i, v in s.data {
		callback(i + s.lower_bound, v)
	}
}

@[inline; _hot]
pub fn (mut s SafeList[T]) len() int {
	s.mtx.rlock()
	defer { s.mtx.runlock() }
	return s.data.len
}

@[inline; _hot]
pub fn (mut s SafeList[T]) is_empty() bool {
	s.mtx.rlock()
	defer { s.mtx.runlock() }
	return s.data.len == 0
}

@[inline; _hot]
pub fn (mut s SafeList[T]) is_full() bool {
	s.mtx.rlock()
	defer { s.mtx.runlock() }
	return s.data.len >= s.capacity
}

@[inline; _hot]
pub fn (mut s SafeList[T]) remaining_capacity() int {
	s.mtx.rlock()
	defer { s.mtx.runlock() }
	return s.capacity - s.data.len
}

@[inline; _hot]
pub fn (mut s SafeList[T]) find(val T) ?int {
	s.mtx.rlock()
	defer { s.mtx.runlock() }
	for i, v in s.data {
		if v == val {
			return i + s.lower_bound
		}
	}
	return none
}

@[inline; _hot]
pub fn (mut s SafeList[T]) contains(val T) bool {
	s.mtx.rlock()
	defer { s.mtx.runlock() }
	for v in s.data {
		if v == val {
			return true
		}
	}
	return false
}

@[packed; minify]
pub struct SafeVar[T] {
	name string
mut:
	val         T
	initialized bool
	frozen      bool
	mtx         &sync.RwMutex = sync.new_rwmutex()
}

@[inline; _hot]
pub fn new_safe_var[T](name string) SafeVar[T] {
	return SafeVar[T]{ name: name }
}

@[inline; _hot]
pub fn new_safe_var_init[T](name string, val T) SafeVar[T] {
	return SafeVar[T]{ name: name, val: val, initialized: true }
}

@[inline; _hot]
pub fn (mut v SafeVar[T]) get() !T {
	v.mtx.rlock()
	defer { v.mtx.runlock() }
	if _unlikely_(!v.initialized) {
		return error('Access_Error: "${v.name}" used before initialization')
	}
	return v.val
}

@[inline; _hot]
pub fn (mut v SafeVar[T]) set(val T) ! {
	v.mtx.lock()
	defer { v.mtx.unlock() }
	if _unlikely_(v.frozen) {
		return error('Frozen_Error: "${v.name}" is frozen')
	}
	v.val = val
	v.initialized = true
}

@[inline; _hot]
pub fn (mut v SafeVar[T]) freeze() ! {
	v.mtx.lock()
	defer { v.mtx.unlock() }
	if _unlikely_(!v.initialized) {
		return error('Freeze_Error: cannot freeze uninitialized "${v.name}"')
	}
	v.frozen = true
}

@[inline; _hot]
pub fn (mut v SafeVar[T]) is_initialized() bool {
	v.mtx.rlock()
	defer { v.mtx.runlock() }
	return v.initialized
}

@[inline; _hot]
pub fn (mut v SafeVar[T]) is_frozen() bool {
	v.mtx.rlock()
	defer { v.mtx.runlock() }
	return v.frozen
}

@[packed; minify]
pub struct ValidatedVar[T] {
	name      string
	validator ?fn (T) bool
	err_msg   string
mut:
	val         T
	initialized bool
	mtx         &sync.RwMutex = sync.new_rwmutex()
}

@[inline; _hot]
pub fn new_validated_var[T](name string, validator fn (T) bool, err_msg string) ValidatedVar[T] {
	return ValidatedVar[T]{ name: name, validator: validator, err_msg: err_msg }
}

@[inline; _hot]
pub fn (mut v ValidatedVar[T]) set(val T) ! {
	v.mtx.lock()
	defer { v.mtx.unlock() }
	validate := v.validator or {
		return error('Validation_Error: "${v.name}" has no validator')
	}
	if _unlikely_(!validate(val)) {
		return error('Validation_Error: "${v.name}" - ${v.err_msg}')
	}
	v.val = val
	v.initialized = true
}

@[inline; _hot]
pub fn (mut v ValidatedVar[T]) get() !T {
	v.mtx.rlock()
	defer { v.mtx.runlock() }
	if _unlikely_(!v.initialized) {
		return error('Access_Error: "${v.name}" not initialized')
	}
	return v.val
}

@[inline; _hot]
pub fn (mut v ValidatedVar[T]) is_initialized() bool {
	v.mtx.rlock()
	defer { v.mtx.runlock() }
	return v.initialized
}

@[inline; _hot]
pub fn require(condition bool, msg string) ! {
	if _unlikely_(!condition) {
		return error('Precondition_Failed: ${msg}')
	}
}

@[inline; _hot]
pub fn ensure(condition bool, msg string) ! {
	if _unlikely_(!condition) {
		return error('Postcondition_Failed: ${msg}')
	}
}

@[inline; _hot]
pub fn check_invariant(condition bool, msg string) ! {
	if _unlikely_(!condition) {
		return error('Invariant_Violated: ${msg}')
	}
}

@[inline; _hot]
pub fn require_all(conditions []bool, messages []string) ! {
	for i, cond in conditions {
		if _unlikely_(!cond) {
			msg := if i < messages.len { messages[i] } else { 'condition ${i}' }
			return error('Precondition_Failed: ${msg}')
		}
	}
}

@[inline; _hot]
pub fn safe_assert(condition bool, context string, detail string) ! {
	if _unlikely_(!condition) {
		return error('Assertion_Error [${context}]: ${detail}')
	}
}

@[inline; _hot]
pub fn safe_add_i64(a i64, b i64) !i64 {
	if _unlikely_(b > 0 && a > vanadium.max_i64_val - b) {
		return error('Overflow_Error: ${a} + ${b}')
	}
	if _unlikely_(b < 0 && a < vanadium.min_i64_val - b) {
		return error('Underflow_Error: ${a} + ${b}')
	}
	return a + b
}

@[inline; _hot]
pub fn safe_sub_i64(a i64, b i64) !i64 {
	if _unlikely_(b > 0 && a < vanadium.min_i64_val + b) {
		return error('Underflow_Error: ${a} - ${b}')
	}
	if _unlikely_(b < 0 && a > vanadium.max_i64_val + b) {
		return error('Overflow_Error: ${a} - ${b}')
	}
	return a - b
}

@[inline; _hot]
pub fn safe_mul_i64(a i64, b i64) !i64 {
	if a == 0 || b == 0 {
		return i64(0)
	}
	if _unlikely_((a > 0 && b > 0 && a > vanadium.max_i64_val / b) || (a < 0 && b < 0 && a < vanadium.max_i64_val / b) || (a > 0 && b < 0 && b < vanadium.min_i64_val / a) || (a < 0 && b > 0 && a < vanadium.min_i64_val / b)) {
		return error('Overflow_Error: ${a} * ${b}')
	}
	return a * b
}

@[inline; _hot]
pub fn safe_div_i64(a i64, b i64) !i64 {
	if _unlikely_(b == 0) {
		return error('Division_Error: ${a} / 0')
	}
	if _unlikely_(a == vanadium.min_i64_val && b == -1) {
		return error('Overflow_Error: ${a} / ${b}')
	}
	return a / b
}

@[inline; _hot]
pub fn safe_mod_i64(a i64, b i64) !i64 {
	if _unlikely_(b == 0) {
		return error('Division_Error: ${a} % 0')
	}
	return a % b
}

@[inline; _hot]
pub fn safe_add_i32(a int, b int) !int {
	result := i64(a) + i64(b)
	if _unlikely_(result > vanadium.max_i32_val || result < vanadium.min_i32_val) {
		return error('Overflow_Error: ${a} + ${b}')
	}
	return int(result)
}

@[inline; _hot]
pub fn safe_sub_i32(a int, b int) !int {
	result := i64(a) - i64(b)
	if _unlikely_(result > vanadium.max_i32_val || result < vanadium.min_i32_val) {
		return error('Overflow_Error: ${a} - ${b}')
	}
	return int(result)
}

@[inline; _hot]
pub fn safe_mul_i32(a int, b int) !int {
	result := i64(a) * i64(b)
	if _unlikely_(result > vanadium.max_i32_val || result < vanadium.min_i32_val) {
		return error('Overflow_Error: ${a} * ${b}')
	}
	return int(result)
}

@[inline; _hot]
pub fn safe_div_i32(a int, b int) !int {
	if _unlikely_(b == 0) {
		return error('Division_Error: ${a} / 0')
	}
	return a / b
}

@[inline; _hot]
pub fn safe_pow(base i64, exp u32) !i64 {
	mut result := i64(1)
	mut b := base
	mut e := exp
	for e > 0 {
		if e & 1 == 1 {
			result = safe_mul_i64(result, b)!
		}
		if e > 1 {
			b = safe_mul_i64(b, b)!
		}
		e >>= 1
	}
	return result
}

@[inline; _hot]
pub fn safe_negate_i64(a i64) !i64 {
	if _unlikely_(a == vanadium.min_i64_val) {
		return error('Overflow_Error: negate ${a}')
	}
	return -a
}

@[inline; _hot]
pub fn safe_abs_i64(a i64) !i64 {
	if _unlikely_(a == vanadium.min_i64_val) {
		return error('Overflow_Error: abs ${a}')
	}
	if a < 0 {
		return -a
	}
	return a
}

@[inline; _hot]
pub fn clamp_i64(val i64, min_v i64, max_v i64) i64 {
	if _unlikely_(val < min_v) {
		return min_v
	}
	if _unlikely_(val > max_v) {
		return max_v
	}
	return val
}

@[packed; minify]
pub struct TimingGuard {
pub:
	target time.Duration
mut:
	sw time.StopWatch
}

@[packed; minify]
pub struct TimingReport {
pub:
	exec_elapsed time.Duration
	padded       time.Duration
	total        time.Duration
	was_padded   bool
	exceeded     bool
}

@[inline; _hot]
pub fn new_timing_guard(target time.Duration) !TimingGuard {
	if _unlikely_(target <= 0) {
		return error('Timing_Error: target duration must be > 0')
	}
	return TimingGuard{
		target: target
		sw: time.new_stopwatch()
	}
}

@[inline; _hot]
pub fn new_timing_guard_ns(ns i64) !TimingGuard {
	return new_timing_guard(ns * time.nanosecond)
}

@[inline; _hot]
pub fn new_timing_guard_us(us i64) !TimingGuard {
	return new_timing_guard(us * time.microsecond)
}

@[inline; _hot]
pub fn new_timing_guard_ms(ms i64) !TimingGuard {
	return new_timing_guard(ms * time.millisecond)
}

@[inline; _hot]
pub fn new_timing_guard_s(s i64) !TimingGuard {
	return new_timing_guard(s * time.second)
}

@[inline; _hot]
pub fn (mut tg TimingGuard) pad() {
	elapsed := tg.sw.elapsed()
	remaining := tg.target - elapsed
	if remaining > 0 {
		time.sleep(remaining)
	}
}

@[inline; _hot]
pub fn (mut tg TimingGuard) pad_report() TimingReport {
	elapsed := tg.sw.elapsed()
	remaining := tg.target - elapsed
	if remaining > 0 {
		time.sleep(remaining)
		return TimingReport{
			exec_elapsed: elapsed
			padded:       remaining
			total:        tg.target
			was_padded:   true
			exceeded:     false
		}
	}
	return TimingReport{
		exec_elapsed: elapsed
		padded:       time.Duration(0)
		total:        elapsed
		was_padded:   false
		exceeded:     elapsed > tg.target
	}
}

@[inline; _hot]
pub fn (mut tg TimingGuard) elapsed() time.Duration {
	return tg.sw.elapsed()
}

@[inline; _hot]
pub fn (mut tg TimingGuard) remaining() time.Duration {
	r := tg.target - tg.sw.elapsed()
	if r < 0 {
		return time.Duration(0)
	}
	return r
}

@[inline; _hot]
pub fn (mut tg TimingGuard) restart() {
	tg.sw.restart()
}

@[inline; _hot]
pub fn (r TimingReport) str() string {
	exec_ms := f64(r.exec_elapsed) / f64(time.millisecond)
	pad_ms := f64(r.padded) / f64(time.millisecond)
	total_ms := f64(r.total) / f64(time.millisecond)
	status := if r.exceeded {
		'EXCEEDED'
	} else if r.was_padded {
		'PADDED'
	} else {
		'EXACT'
	}
	return 'TimingReport{ exec: ${exec_ms:.2}ms, pad: ${pad_ms:.2}ms, total: ${total_ms:.2}ms, status: ${status} }'
}

@[inline; _hot]
pub fn timed_call(target time.Duration, callback fn ()) ! {
	if _unlikely_(target <= 0) {
		return error('Timing_Error: target duration must be > 0')
	}
	sw := time.new_stopwatch()
	callback()
	remaining := target - sw.elapsed()
	if remaining > 0 {
		time.sleep(remaining)
	}
}

@[inline; _hot]
pub fn timed_call_ms(ms i64, callback fn ()) ! {
	timed_call(ms * time.millisecond, callback)!
}

@[inline; _hot]
pub fn timed_call_s(s i64, callback fn ()) ! {
	timed_call(s * time.second, callback)!
}

@[inline; _hot]
pub fn timed_call_report(target time.Duration, callback fn ()) !TimingReport {
	if _unlikely_(target <= 0) {
		return error('Timing_Error: target duration must be > 0')
	}
	sw := time.new_stopwatch()
	callback()
	elapsed := sw.elapsed()
	remaining := target - elapsed
	if remaining > 0 {
		time.sleep(remaining)
		return TimingReport{
			exec_elapsed: elapsed
			padded:       remaining
			total:        target
			was_padded:   true
			exceeded:     false
		}
	}
	return TimingReport{
		exec_elapsed: elapsed
		padded:       time.Duration(0)
		total:        elapsed
		was_padded:   false
		exceeded:     elapsed > target
	}
}

@[inline; _hot]
pub fn constant_time_eq(a []u8, b []u8) bool {
	if a.len != b.len {
		return false
	}
	mut diff := u8(0)
	for i in 0 .. a.len {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

@[inline; _hot]
pub fn constant_time_eq_strings(a string, b string) bool {
	return constant_time_eq(a.bytes(), b.bytes())
}


const hardened_true_pattern = u64(0xAAAAAAAAAAAAAAAA)
const hardened_false_pattern = u64(0x5555555555555555)

@[packed; minify]
pub struct HardenedI64 {
mut:
	val   i64
	guard i64
}

@[inline; _hot]
pub fn new_hardened_i64(v i64) HardenedI64 {
	return HardenedI64{
		val:   v
		guard: ~v
	}
}

@[inline; _hot]
pub fn (h HardenedI64) get() !i64 {
	if _unlikely_(h.val != ~h.guard) {
		return error('Memory_Corruption: i64 bit-flip detected')
	}
	return h.val
}

@[inline; _hot]
pub fn (mut h HardenedI64) set(v i64) {
	h.val = v
	h.guard = ~v
}

@[inline; _hot]
pub fn (h HardenedI64) verify() bool {
	return h.val == ~h.guard
}

@[inline; _hot]
pub fn (h HardenedI64) checked_add(other i64) !HardenedI64 {
	v := h.get()!
	if _unlikely_((other > 0 && v > vanadium.max_i64_val - other)
		|| (other < 0 && v < vanadium.min_i64_val - other)) {
		return error('Overflow_Error: ${v} + ${other}')
	}
	return new_hardened_i64(v + other)
}

@[inline; _hot]
pub fn (h HardenedI64) checked_sub(other i64) !HardenedI64 {
	v := h.get()!
	if _unlikely_((other > 0 && v < vanadium.min_i64_val + other)
		|| (other < 0 && v > vanadium.max_i64_val + other)) {
		return error('Overflow_Error: ${v} - ${other}')
	}
	return new_hardened_i64(v - other)
}

@[inline; _hot]
pub fn (h HardenedI64) checked_mul(other i64) !HardenedI64 {
	v := h.get()!
	if v != 0 && other != 0 {
		if _unlikely_((v > 0 && other > 0 && v > vanadium.max_i64_val / other)
			|| (v < 0 && other < 0 && v < vanadium.max_i64_val / other)
			|| (v > 0 && other < 0 && other < vanadium.min_i64_val / v)
			|| (v < 0 && other > 0 && v < vanadium.min_i64_val / other)) {
			return error('Overflow_Error: ${v} * ${other}')
		}
	}
	return new_hardened_i64(v * other)
}

@[inline; _hot]
pub fn (h HardenedI64) checked_div(other i64) !HardenedI64 {
	v := h.get()!
	if _unlikely_(other == 0) {
		return error('Division_Error: division by zero')
	}
	if _unlikely_(v == vanadium.min_i64_val && other == -1) {
		return error('Overflow_Error: ${v} / ${other}')
	}
	return new_hardened_i64(v / other)
}

@[inline; _hot]
pub fn (h HardenedI64) str() string {
	v := h.get() or { return 'CORRUPTED' }
	return '${v} (hardened)'
}

@[packed; minify]
pub struct HardenedBool {
mut:
	val   u64
	guard u64
}

@[inline; _hot]
pub fn new_hardened_bool(v bool) HardenedBool {
	raw := if v { hardened_true_pattern } else { hardened_false_pattern }
	return HardenedBool{
		val:   raw
		guard: ~raw
	}
}

@[inline; _hot]
pub fn (h HardenedBool) get() !bool {
	if _unlikely_(h.val != ~h.guard) {
		return error('Memory_Corruption: bool integrity failed')
	}
	if h.val == hardened_true_pattern {
		return true
	}
	if h.val == hardened_false_pattern {
		return false
	}
	return error('Memory_Corruption: bool in unknown state')
}

@[inline; _hot]
pub fn (mut h HardenedBool) set(v bool) {
	raw := if v { hardened_true_pattern } else { hardened_false_pattern }
	h.val = raw
	h.guard = ~raw
}

@[inline; _hot]
pub fn (h HardenedBool) verify() bool {
	if h.val != ~h.guard {
		return false
	}
	return h.val == hardened_true_pattern || h.val == hardened_false_pattern
}

@[inline; _hot]
pub fn (h HardenedBool) str() string {
	v := h.get() or { return 'CORRUPTED' }
	return '${v} (hardened)'
}

@[packed; minify]
pub struct HardenedRangedInt {
mut:
	val       i64
	min       i64
	max       i64
	val_guard i64
	min_guard i64
	max_guard i64
}

@[inline; _hot]
fn (h HardenedRangedInt) integrity_check() ! {
	if _unlikely_(h.val != ~h.val_guard) {
		return error('Memory_Corruption: value bit-flip detected')
	}
	if _unlikely_(h.min != ~h.min_guard) {
		return error('Memory_Corruption: min bound bit-flip detected')
	}
	if _unlikely_(h.max != ~h.max_guard) {
		return error('Memory_Corruption: max bound bit-flip detected')
	}
}

@[inline; _hot]
pub fn HardenedRangedInt.create(min_v i64, max_v i64, initial i64) !HardenedRangedInt {
	if _unlikely_(min_v > max_v) {
		return error('Range_Error: min > max')
	}
	if _unlikely_(initial < min_v || initial > max_v) {
		return error('Constraint_Error: ${initial} not in ${min_v}..${max_v}')
	}
	return HardenedRangedInt{
		val:       initial
		min:       min_v
		max:       max_v
		val_guard: ~initial
		min_guard: ~min_v
		max_guard: ~max_v
	}
}

@[inline; _hot]
pub fn (h HardenedRangedInt) value() !i64 {
	h.integrity_check()!
	return h.val
}

@[inline; _hot]
pub fn (h HardenedRangedInt) min_val() !i64 {
	h.integrity_check()!
	return h.min
}

@[inline; _hot]
pub fn (h HardenedRangedInt) max_val() !i64 {
	h.integrity_check()!
	return h.max
}

@[inline; _hot]
pub fn (h HardenedRangedInt) in_range(v i64) !bool {
	h.integrity_check()!
	return v >= h.min && v <= h.max
}

@[inline; _hot]
pub fn (mut h HardenedRangedInt) assign(v i64) ! {
	h.integrity_check()!
	if _unlikely_(v < h.min || v > h.max) {
		return error('Constraint_Error: ${v} not in ${h.min}..${h.max}')
	}
	h.val = v
	h.val_guard = ~v
}

@[inline; _hot]
pub fn (h HardenedRangedInt) checked_add(other i64) !HardenedRangedInt {
	h.integrity_check()!
	if _unlikely_((other > 0 && h.val > vanadium.max_i64_val - other)
		|| (other < 0 && h.val < vanadium.min_i64_val - other)) {
		return error('Overflow_Error: ${h.val} + ${other}')
	}
	result := h.val + other
	if _unlikely_(result < h.min || result > h.max) {
		return error('Constraint_Error: ${h.val} + ${other} = ${result} not in ${h.min}..${h.max}')
	}
	return HardenedRangedInt{
		val:       result
		min:       h.min
		max:       h.max
		val_guard: ~result
		min_guard: h.min_guard
		max_guard: h.max_guard
	}
}

@[inline; _hot]
pub fn (h HardenedRangedInt) checked_sub(other i64) !HardenedRangedInt {
	h.integrity_check()!
	if _unlikely_((other > 0 && h.val < vanadium.min_i64_val + other)
		|| (other < 0 && h.val > vanadium.max_i64_val + other)) {
		return error('Overflow_Error: ${h.val} - ${other}')
	}
	result := h.val - other
	if _unlikely_(result < h.min || result > h.max) {
		return error('Constraint_Error: ${h.val} - ${other} = ${result} not in ${h.min}..${h.max}')
	}
	return HardenedRangedInt{
		val:       result
		min:       h.min
		max:       h.max
		val_guard: ~result
		min_guard: h.min_guard
		max_guard: h.max_guard
	}
}

@[inline; _hot]
pub fn (h HardenedRangedInt) checked_mul(other i64) !HardenedRangedInt {
	h.integrity_check()!
	if h.val != 0 && other != 0 {
		if _unlikely_((h.val > 0 && other > 0 && h.val > vanadium.max_i64_val / other)
			|| (h.val < 0 && other < 0 && h.val < vanadium.max_i64_val / other)
			|| (h.val > 0 && other < 0 && other < vanadium.min_i64_val / h.val)
			|| (h.val < 0 && other > 0 && h.val < vanadium.min_i64_val / other)) {
			return error('Overflow_Error: ${h.val} * ${other}')
		}
	}
	result := h.val * other
	if _unlikely_(result < h.min || result > h.max) {
		return error('Constraint_Error: ${h.val} * ${other} = ${result} not in ${h.min}..${h.max}')
	}
	return HardenedRangedInt{
		val:       result
		min:       h.min
		max:       h.max
		val_guard: ~result
		min_guard: h.min_guard
		max_guard: h.max_guard
	}
}

@[inline; _hot]
pub fn (h HardenedRangedInt) checked_div(other i64) !HardenedRangedInt {
	h.integrity_check()!
	if _unlikely_(other == 0) {
		return error('Division_Error: division by zero')
	}
	if _unlikely_(h.val == vanadium.min_i64_val && other == -1) {
		return error('Overflow_Error: ${h.val} / ${other}')
	}
	result := h.val / other
	if _unlikely_(result < h.min || result > h.max) {
		return error('Constraint_Error: ${h.val} / ${other} = ${result} not in ${h.min}..${h.max}')
	}
	return HardenedRangedInt{
		val:       result
		min:       h.min
		max:       h.max
		val_guard: ~result
		min_guard: h.min_guard
		max_guard: h.max_guard
	}
}

@[inline; _hot]
pub fn (h HardenedRangedInt) str() string {
	h.integrity_check() or { return 'CORRUPTED' }
	return '${h.val} in [${h.min}..${h.max}] (hardened)'
}

@[inline; _hot]
pub fn safe_index_mask(index int, length int) int {
	pos_mask := ~(index >> 31)
	bound_mask := (index - length) >> 31
	return index & (pos_mask & bound_mask)
}

@[inline; _hot]
pub fn safe_index_mask_64(index i64, length i64) i64 {
	pos_mask := ~(index >> 63)
	bound_mask := (index - length) >> 63
	return index & (pos_mask & bound_mask)
}

@[inline; _hot]
pub fn simulate_corrupted_bool() HardenedBool {
	return HardenedBool{
		val:   hardened_true_pattern
		guard: u64(0)
	}
}

@[inline; _hot]
pub fn simulate_corrupted_i64(fake_val i64, real_val i64) HardenedI64 {
	return HardenedI64{
		val:   fake_val
		guard: ~real_val
	}
}

@[inline; _hot]
pub fn simulate_corrupted_ranged(fake_val i64, real_val i64, min_v i64, max_v i64) HardenedRangedInt {
	return HardenedRangedInt{
		val:       fake_val
		min:       min_v
		max:       max_v
		val_guard: ~real_val
		min_guard: ~min_v
		max_guard: ~max_v
	}
}