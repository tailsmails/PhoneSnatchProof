module vanadium

import time

fn test_ranged_create_valid() {
	r := RangedInt.create(1, 12, 6) or { panic(err.str()) }
	assert r.value() == 6
	assert r.min == 1
	assert r.max == 12
}

fn test_ranged_create_at_bounds() {
	r1 := RangedInt.create(0, 100, 0) or { panic(err.str()) }
	assert r1.value() == 0
	r2 := RangedInt.create(0, 100, 100) or { panic(err.str()) }
	assert r2.value() == 100
}

fn test_ranged_create_invalid_range() {
	if _ := RangedInt.create(10, 5, 7) {
		assert false
	}
}

fn test_ranged_create_out_of_range() {
	if _ := RangedInt.create(1, 12, 13) {
		assert false
	}
	if _ := RangedInt.create(1, 12, 0) {
		assert false
	}
}

fn test_ranged_assign_valid() {
	mut r := RangedInt.create(1, 12, 1) or { panic(err.str()) }
	r.assign(12) or { panic(err.str()) }
	assert r.value() == 12
	r.assign(1) or { panic(err.str()) }
	assert r.value() == 1
}

fn test_ranged_assign_invalid() {
	mut r := RangedInt.create(1, 12, 6) or { panic(err.str()) }
	
	mut err1 := false
	r.assign(13) or { err1 = true }
	assert err1
	
	mut err2 := false
	r.assign(0) or { err2 = true }
	assert err2
	
	assert r.value() == 6
}

fn test_ranged_checked_add() {
	r := RangedInt.create(-10, 10, 5) or { panic(err.str()) }
	r2 := r.checked_add(3) or { panic(err.str()) }
	assert r2.value() == 8
	r3 := r.checked_add(-10) or { panic(err.str()) }
	assert r3.value() == -5
}

fn test_ranged_checked_add_overflow() {
	r := RangedInt.create(-10, 10, 8) or { panic(err.str()) }
	if _ := r.checked_add(5) {
		assert false
	}
}

fn test_ranged_checked_sub() {
	r := RangedInt.create(0, 100, 50) or { panic(err.str()) }
	r2 := r.checked_sub(30) or { panic(err.str()) }
	assert r2.value() == 20
}

fn test_ranged_checked_sub_underflow() {
	r := RangedInt.create(0, 100, 10) or { panic(err.str()) }
	if _ := r.checked_sub(20) {
		assert false
	}
}

fn test_ranged_checked_mul() {
	r := RangedInt.create(-100, 100, 7) or { panic(err.str()) }
	r2 := r.checked_mul(10) or { panic(err.str()) }
	assert r2.value() == 70
}

fn test_ranged_checked_mul_overflow() {
	r := RangedInt.create(-100, 100, 50) or { panic(err.str()) }
	if _ := r.checked_mul(3) {
		assert false
	}
}

fn test_ranged_checked_div() {
	r := RangedInt.create(-100, 100, 84) or { panic(err.str()) }
	r2 := r.checked_div(4) or { panic(err.str()) }
	assert r2.value() == 21
}

fn test_ranged_checked_div_by_zero() {
	r := RangedInt.create(-100, 100, 50) or { panic(err.str()) }
	if _ := r.checked_div(0) {
		assert false
	}
}

fn test_ranged_in_range() {
	r := RangedInt.create(1, 12, 6) or { panic(err.str()) }
	assert r.in_range(1) == true
	assert r.in_range(12) == true
	assert r.in_range(6) == true
	assert r.in_range(0) == false
	assert r.in_range(13) == false
}

fn test_ranged_negative_range() {
	r := RangedInt.create(-40, 85, -20) or { panic(err.str()) }
	assert r.value() == -20
	r2 := r.checked_add(100) or { panic(err.str()) }
	assert r2.value() == 80
}

fn test_ranged_str() {
	r := RangedInt.create(1, 12, 6) or { panic(err.str()) }
	assert r.str() == '6 in [1..12]'
}

fn test_safelist_create() {
	mut s := new_safe_list[int](5) or { panic(err.str()) }
	assert s.len() == 0
	assert s.capacity == 5
	assert s.is_empty() == true
}

fn test_safelist_create_invalid() {
	if _ := new_safe_list[int](0) {
		assert false
	}
	if _ := new_safe_list[int](-1) {
		assert false
	}
}

fn test_safelist_append_and_at() {
	mut s := new_safe_list[int](3) or { panic(err.str()) }
	s.append(10) or { panic(err.str()) }
	s.append(20) or { panic(err.str()) }
	s.append(30) or { panic(err.str()) }
	assert s.at(1) or { panic(err.str()) } == 10
	assert s.at(2) or { panic(err.str()) } == 20
	assert s.at(3) or { panic(err.str()) } == 30
	assert s.len() == 3
	assert s.is_full() == true
}

fn test_safelist_append_overflow() {
	mut s := new_safe_list[int](2) or { panic(err.str()) }
	s.append(1) or { panic(err.str()) }
	s.append(2) or { panic(err.str()) }
	mut failed := false
	s.append(3) or { failed = true }
	assert failed
}

fn test_safelist_at_out_of_bounds() {
	mut s := new_safe_list[int](5) or { panic(err.str()) }
	s.append(10) or { panic(err.str()) }
	s.append(20) or { panic(err.str()) }
	if _ := s.at(0) {
		assert false
	}
	if _ := s.at(3) {
		assert false
	}
	if _ := s.at(-1) {
		assert false
	}
}

fn test_safelist_at_empty() {
	mut s := new_safe_list[int](5) or { panic(err.str()) }
	if _ := s.at(1) {
		assert false
	}
}

fn test_safelist_set_at() {
	mut s := new_safe_list[int](3) or { panic(err.str()) }
	s.append(10) or { panic(err.str()) }
	s.append(20) or { panic(err.str()) }
	s.set_at(1, 99) or { panic(err.str()) }
	assert s.at(1) or { panic(err.str()) } == 99
	assert s.at(2) or { panic(err.str()) } == 20
}

fn test_safelist_set_at_invalid() {
	mut s := new_safe_list[int](3) or { panic(err.str()) }
	s.append(10) or { panic(err.str()) }
	mut failed := false
	s.set_at(5, 99) or { failed = true }
	assert failed
}

fn test_safelist_remove_at() {
	mut s := new_safe_list[int](5) or { panic(err.str()) }
	s.append(10) or { panic(err.str()) }
	s.append(20) or { panic(err.str()) }
	s.append(30) or { panic(err.str()) }
	val := s.remove_at(2) or { panic(err.str()) }
	assert val == 20
	assert s.len() == 2
	assert s.at(1) or { panic(err.str()) } == 10
	assert s.at(2) or { panic(err.str()) } == 30
}

fn test_safelist_first_last() {
	mut s := new_safe_list[int](5) or { panic(err.str()) }
	s.append(10) or { panic(err.str()) }
	s.append(20) or { panic(err.str()) }
	s.append(30) or { panic(err.str()) }
	assert s.first() or { panic(err.str()) } == 10
	assert s.last() or { panic(err.str()) } == 30
}

fn test_safelist_first_last_empty() {
	mut s := new_safe_list[int](5) or { panic(err.str()) }
	if _ := s.first() {
		assert false
	}
	if _ := s.last() {
		assert false
	}
}

fn test_safelist_pop() {
	mut s := new_safe_list[int](5) or { panic(err.str()) }
	s.append(10) or { panic(err.str()) }
	s.append(20) or { panic(err.str()) }
	val := s.pop() or { panic(err.str()) }
	assert val == 20
	assert s.len() == 1
}

fn test_safelist_pop_empty() {
	mut s := new_safe_list[int](5) or { panic(err.str()) }
	if _ := s.pop() {
		assert false
	}
}

fn test_safelist_append_many() {
	mut s := new_safe_list[int](5) or { panic(err.str()) }
	s.append_many([1, 2, 3]) or { panic(err.str()) }
	assert s.len() == 3
	
	mut failed := false
	s.append_many([4, 5, 6]) or { failed = true }
	assert failed
	
	s.append_many([4, 5]) or { panic(err.str()) }
	assert s.len() == 5
	assert s.is_full() == true
}

fn test_safelist_bounded() {
	mut s := new_bounded_list[int](3, 5) or { panic(err.str()) }
	s.append(100) or { panic(err.str()) }
	s.append(200) or { panic(err.str()) }
	s.append(300) or { panic(err.str()) }
	assert s.at(5) or { panic(err.str()) } == 100
	assert s.at(6) or { panic(err.str()) } == 200
	assert s.at(7) or { panic(err.str()) } == 300
	if _ := s.at(4) {
		assert false
	}
	if _ := s.at(8) {
		assert false
	}
}

fn test_safelist_find() {
	mut s := new_safe_list[int](5) or { panic(err.str()) }
	s.append(10) or { panic(err.str()) }
	s.append(20) or { panic(err.str()) }
	s.append(30) or { panic(err.str()) }
	
	idx := s.find(20) or { -1 }
	assert idx == 2
	
	idx_none := s.find(99) or { -1 }
	assert idx_none == -1
}

fn test_safelist_contains() {
	mut s := new_safe_list[int](5) or { panic(err.str()) }
	s.append(10) or { panic(err.str()) }
	s.append(20) or { panic(err.str()) }
	assert s.contains(10) == true
	assert s.contains(99) == false
}

fn test_safelist_remaining_capacity() {
	mut s := new_safe_list[int](5) or { panic(err.str()) }
	assert s.remaining_capacity() == 5
	s.append(1) or { panic(err.str()) }
	assert s.remaining_capacity() == 4
	s.append(2) or { panic(err.str()) }
	s.append(3) or { panic(err.str()) }
	assert s.remaining_capacity() == 2
}

fn test_safelist_slice() {
	mut s := new_safe_list[int](10) or { panic(err.str()) }
	s.append_many([10, 20, 30, 40, 50]) or { panic(err.str()) }
	mut sl := s.safe_slice(2, 4) or { panic(err.str()) }
	assert sl.len() == 3
	assert sl.at(2) or { panic(err.str()) } == 20
	assert sl.at(3) or { panic(err.str()) } == 30
	assert sl.at(4) or { panic(err.str()) } == 40
}

fn test_safelist_slice_invalid() {
	mut s := new_safe_list[int](5) or { panic(err.str()) }
	s.append_many([10, 20, 30]) or { panic(err.str()) }
	if _ := s.safe_slice(3, 1) {
		assert false
	}
	if _ := s.safe_slice(0, 2) {
		assert false
	}
	if _ := s.safe_slice(1, 5) {
		assert false
	}
}

fn test_safelist_string_type() {
	mut s := new_safe_list[string](3) or { panic(err.str()) }
	s.append('hello') or { panic(err.str()) }
	s.append('world') or { panic(err.str()) }
	assert s.at(1) or { panic(err.str()) } == 'hello'
	assert s.at(2) or { panic(err.str()) } == 'world'
	assert s.contains('hello') == true
	assert s.contains('foo') == false
}

fn test_safelist_each() {
	mut s := new_safe_list[int](5) or { panic(err.str()) }
	s.append_many([10, 20, 30]) or { panic(err.str()) }
	s.each(fn (idx int, val int) {
		if idx == 1 {
			assert val == 10
		}
		if idx == 2 {
			assert val == 20
		}
		if idx == 3 {
			assert val == 30
		}
		assert idx >= 1 && idx <= 3
	})
}

fn test_safevar_uninitialized() {
	mut v := new_safe_var[int]('x')
	assert v.is_initialized() == false
	if _ := v.get() {
		assert false
	}
}

fn test_safevar_set_get() {
	mut v := new_safe_var[int]('x')
	v.set(42) or { panic(err.str()) }
	assert v.is_initialized() == true
	assert v.get() or { panic(err.str()) } == 42
}

fn test_safevar_init() {
	mut v := new_safe_var_init[string]('name', 'test')
	assert v.is_initialized() == true
	assert v.get() or { panic(err.str()) } == 'test'
}

fn test_safevar_freeze() {
	mut v := new_safe_var_init[int]('const_val', 100)
	v.freeze() or { panic(err.str()) }
	assert v.is_frozen() == true
	
	mut failed := false
	v.set(200) or { failed = true }
	assert failed
	
	assert v.get() or { panic(err.str()) } == 100
}

fn test_safevar_freeze_uninitialized() {
	mut v := new_safe_var[int]('x')
	mut failed := false
	v.freeze() or { failed = true }
	assert failed
}

fn test_validated_var() {
	mut age := new_validated_var[int]('age', fn (v int) bool {
		return v >= 0 && v <= 150
	}, 'must be 0..150')
	age.set(25) or { panic(err.str()) }
	assert age.get() or { panic(err.str()) } == 25
	
	mut err1 := false
	age.set(-1) or { err1 = true }
	assert err1
	
	mut err2 := false
	age.set(200) or { err2 = true }
	assert err2
	
	assert age.get() or { panic(err.str()) } == 25
}

fn test_validated_var_uninitialized() {
	mut v := new_validated_var[int]('x', fn (v int) bool {
		return true
	}, '')
	if _ := v.get() {
		assert false
	}
}

fn test_require() {
	require(true, 'ok') or { panic(err.str()) }
	mut failed := false
	require(false, 'should fail') or { failed = true }
	assert failed
}

fn test_ensure() {
	ensure(true, 'ok') or { panic(err.str()) }
	mut failed := false
	ensure(false, 'should fail') or { failed = true }
	assert failed
}

fn test_check_invariant() {
	check_invariant(true, 'ok') or { panic(err.str()) }
	mut failed := false
	check_invariant(false, 'broken') or { failed = true }
	assert failed
}

fn test_require_all() {
	require_all([true, true, true], ['a', 'b', 'c']) or { panic(err.str()) }
	mut failed := false
	require_all([true, false, true], ['a', 'b', 'c']) or { failed = true }
	assert failed
}

fn test_safe_assert() {
	safe_assert(true, 'test', 'ok') or { panic(err.str()) }
	mut failed := false
	safe_assert(false, 'test', 'fail') or { failed = true }
	assert failed
}

fn test_safe_add_i64() {
	assert (safe_add_i64(1, 2) or { panic(err.str()) }) == 3
	assert (safe_add_i64(-5, 3) or { panic(err.str()) }) == -2
	assert (safe_add_i64(0, 0) or { panic(err.str()) }) == 0
	if _ := safe_add_i64(max_i64_val, 1) {
		assert false
	}
	if _ := safe_add_i64(min_i64_val, -1) {
		assert false
	}
}

fn test_safe_sub_i64() {
	assert (safe_sub_i64(10, 3) or { panic(err.str()) }) == 7
	assert (safe_sub_i64(-5, -3) or { panic(err.str()) }) == -2
	if _ := safe_sub_i64(min_i64_val, 1) {
		assert false
	}
}

fn test_safe_mul_i64() {
	assert (safe_mul_i64(6, 7) or { panic(err.str()) }) == 42
	assert (safe_mul_i64(0, 999) or { panic(err.str()) }) == 0
	assert (safe_mul_i64(-3, 4) or { panic(err.str()) }) == -12
	if _ := safe_mul_i64(max_i64_val, 2) {
		assert false
	}
}

fn test_safe_div_i64() {
	assert (safe_div_i64(10, 3) or { panic(err.str()) }) == 3
	assert (safe_div_i64(-10, 2) or { panic(err.str()) }) == -5
	if _ := safe_div_i64(10, 0) {
		assert false
	}
	if _ := safe_div_i64(min_i64_val, -1) {
		assert false
	}
}

fn test_safe_mod_i64() {
	assert (safe_mod_i64(10, 3) or { panic(err.str()) }) == 1
	if _ := safe_mod_i64(10, 0) {
		assert false
	}
}

fn test_safe_add_i32() {
	assert (safe_add_i32(100, 200) or { panic(err.str()) }) == 300
	if _ := safe_add_i32(2000000000, 1000000000) {
		assert false
	}
}

fn test_safe_sub_i32() {
	assert (safe_sub_i32(100, 50) or { panic(err.str()) }) == 50
	if _ := safe_sub_i32(-2000000000, 1000000000) {
		assert false
	}
}

fn test_safe_mul_i32() {
	assert (safe_mul_i32(100, 200) or { panic(err.str()) }) == 20000
	if _ := safe_mul_i32(100000, 100000) {
		assert false
	}
}

fn test_safe_div_i32() {
	assert (safe_div_i32(10, 3) or { panic(err.str()) }) == 3
	if _ := safe_div_i32(10, 0) {
		assert false
	}
}

fn test_safe_pow() {
	assert (safe_pow(2, 10) or { panic(err.str()) }) == 1024
	assert (safe_pow(2, 0) or { panic(err.str()) }) == 1
	assert (safe_pow(3, 3) or { panic(err.str()) }) == 27
	assert (safe_pow(1, 100) or { panic(err.str()) }) == 1
	assert (safe_pow(0, 5) or { panic(err.str()) }) == 0
	if _ := safe_pow(2, 63) {
		assert false
	}
}

fn test_safe_negate_i64() {
	assert (safe_negate_i64(5) or { panic(err.str()) }) == -5
	assert (safe_negate_i64(-5) or { panic(err.str()) }) == 5
	assert (safe_negate_i64(0) or { panic(err.str()) }) == 0
	if _ := safe_negate_i64(min_i64_val) {
		assert false
	}
}

fn test_safe_abs_i64() {
	assert (safe_abs_i64(5) or { panic(err.str()) }) == 5
	assert (safe_abs_i64(-5) or { panic(err.str()) }) == 5
	assert (safe_abs_i64(0) or { panic(err.str()) }) == 0
	if _ := safe_abs_i64(min_i64_val) {
		assert false
	}
}

fn test_clamp_i64() {
	assert clamp_i64(5, 0, 10) == 5
	assert clamp_i64(-5, 0, 10) == 0
	assert clamp_i64(15, 0, 10) == 10
	assert clamp_i64(0, 0, 10) == 0
	assert clamp_i64(10, 0, 10) == 10
}

fn test_full_workflow() {
	mut balance := RangedInt.create(0, 1000000, 5000) or { panic(err.str()) }
	mut history := new_safe_list[string](100) or { panic(err.str()) }

	balance = balance.checked_add(1500) or { panic(err.str()) }
	history.append('deposit 1500') or { panic(err.str()) }
	assert balance.value() == 6500

	balance = balance.checked_sub(2000) or { panic(err.str()) }
	history.append('withdraw 2000') or { panic(err.str()) }
	assert balance.value() == 4500

	if _ := balance.checked_sub(5000) {
		assert false
	}

	assert history.len() == 2
	assert history.at(1) or { panic(err.str()) } == 'deposit 1500'
	assert history.at(2) or { panic(err.str()) } == 'withdraw 2000'
}

fn test_timing_guard_create_valid() {
	_ := new_timing_guard_ms(100) or { panic(err.str()) }
	_ := new_timing_guard_s(1) or { panic(err.str()) }
	_ := new_timing_guard_us(500) or { panic(err.str()) }
	_ := new_timing_guard_ns(1000000) or { panic(err.str()) }
	_ := new_timing_guard(50 * time.millisecond) or { panic(err.str()) }
}

fn test_timing_guard_create_invalid() {
	if _ := new_timing_guard(0) {
		assert false
	}
	if _ := new_timing_guard(-1 * time.millisecond) {
		assert false
	}
	if _ := new_timing_guard_ms(0) {
		assert false
	}
	if _ := new_timing_guard_s(0) {
		assert false
	}
	if _ := new_timing_guard_us(0) {
		assert false
	}
	if _ := new_timing_guard_ns(0) {
		assert false
	}
}

fn test_timing_guard_pad_basic() {
	sw := time.new_stopwatch()
	mut guard := new_timing_guard_ms(300) or { panic(err.str()) }
	time.sleep(50 * time.millisecond)
	guard.pad()
	elapsed := sw.elapsed()
	assert elapsed >= 280 * time.millisecond
	assert elapsed < 500 * time.millisecond
}

fn test_timing_guard_pad_no_sleep_needed() {
	mut guard := new_timing_guard_ms(50) or { panic(err.str()) }
	time.sleep(100 * time.millisecond)
	sw := time.new_stopwatch()
	guard.pad()
	pad_time := sw.elapsed()
	assert pad_time < 30 * time.millisecond
}

fn test_timing_guard_pad_report_padded() {
	mut guard := new_timing_guard_ms(300) or { panic(err.str()) }
	time.sleep(50 * time.millisecond)
	report := guard.pad_report()
	assert report.was_padded == true
	assert report.exceeded == false
	assert report.exec_elapsed > 40 * time.millisecond
	assert report.exec_elapsed < 200 * time.millisecond
	assert report.padded > 0
	assert report.total == 300 * time.millisecond
}

fn test_timing_guard_pad_report_exceeded() {
	mut guard := new_timing_guard_ms(50) or { panic(err.str()) }
	time.sleep(120 * time.millisecond)
	report := guard.pad_report()
	assert report.was_padded == false
	assert report.exceeded == true
	assert report.exec_elapsed >= 100 * time.millisecond
	assert report.padded == time.Duration(0)
	assert report.total == report.exec_elapsed
}

fn test_timing_guard_elapsed() {
	mut guard := new_timing_guard_ms(500) or { panic(err.str()) }
	time.sleep(80 * time.millisecond)
	e := guard.elapsed()
	assert e >= 60 * time.millisecond
	assert e < 300 * time.millisecond
}

fn test_timing_guard_remaining() {
	mut guard := new_timing_guard_ms(500) or { panic(err.str()) }
	time.sleep(80 * time.millisecond)
	r := guard.remaining()
	assert r > 0
	assert r < 500 * time.millisecond
}

fn test_timing_guard_remaining_zero_when_exceeded() {
	mut guard := new_timing_guard_ms(50) or { panic(err.str()) }
	time.sleep(120 * time.millisecond)
	assert guard.remaining() == time.Duration(0)
}

fn test_timing_guard_restart() {
	mut guard := new_timing_guard_ms(500) or { panic(err.str()) }
	time.sleep(100 * time.millisecond)
	guard.restart()
	r := guard.remaining()
	assert r > 450 * time.millisecond
}

fn test_timing_guard_multiple_restarts() {
	mut guard := new_timing_guard_ms(200) or { panic(err.str()) }
	sw := time.new_stopwatch()
	time.sleep(50 * time.millisecond)
	guard.restart()
	time.sleep(50 * time.millisecond)
	guard.pad()
	total := sw.elapsed()
	assert total >= 240 * time.millisecond
}

fn test_timing_report_str_padded() {
	report := TimingReport{
		exec_elapsed: 100 * time.millisecond
		padded:       200 * time.millisecond
		total:        300 * time.millisecond
		was_padded:   true
		exceeded:     false
	}
	s := report.str()
	assert s.contains('PADDED')
	assert s.contains('TimingReport')
}

fn test_timing_report_str_exceeded() {
	report := TimingReport{
		exec_elapsed: 500 * time.millisecond
		padded:       time.Duration(0)
		total:        500 * time.millisecond
		was_padded:   false
		exceeded:     true
	}
	s := report.str()
	assert s.contains('EXCEEDED')
}

fn test_timing_report_str_exact() {
	report := TimingReport{
		exec_elapsed: 300 * time.millisecond
		padded:       time.Duration(0)
		total:        300 * time.millisecond
		was_padded:   false
		exceeded:     false
	}
	s := report.str()
	assert s.contains('EXACT')
}

fn test_timed_call_pads_correctly() {
	sw := time.new_stopwatch()
	timed_call_ms(300, fn () {
		time.sleep(50 * time.millisecond)
	}) or { panic(err.str()) }
	elapsed := sw.elapsed()
	assert elapsed >= 280 * time.millisecond
	assert elapsed < 500 * time.millisecond
}

fn test_timed_call_no_pad_when_exceeded() {
	sw := time.new_stopwatch()
	timed_call_ms(50, fn () {
		time.sleep(120 * time.millisecond)
	}) or { panic(err.str()) }
	elapsed := sw.elapsed()
	assert elapsed >= 100 * time.millisecond
	assert elapsed < 300 * time.millisecond
}

fn test_timed_call_s() {
	sw := time.new_stopwatch()
	timed_call_s(1, fn () {
		time.sleep(50 * time.millisecond)
	}) or { panic(err.str()) }
	elapsed := sw.elapsed()
	assert elapsed >= 950 * time.millisecond
	assert elapsed < 1500 * time.millisecond
}

fn test_timed_call_invalid_duration() {
	mut err1 := false
	timed_call_ms(0, fn () {}) or { err1 = true }
	assert err1
	
	mut err2 := false
	timed_call(time.Duration(0), fn () {}) or { err2 = true }
	assert err2
	
	mut err3 := false
	timed_call(-1 * time.millisecond, fn () {}) or { err3 = true }
	assert err3
}

fn test_timed_call_report_padded() {
	report := timed_call_report(300 * time.millisecond, fn () {
		time.sleep(50 * time.millisecond)
	}) or { panic(err.str()) }
	assert report.was_padded == true
	assert report.exceeded == false
	assert report.exec_elapsed > 40 * time.millisecond
	assert report.padded > 0
	assert report.total == 300 * time.millisecond
}

fn test_timed_call_report_exceeded() {
	report := timed_call_report(50 * time.millisecond, fn () {
		time.sleep(120 * time.millisecond)
	}) or { panic(err.str()) }
	assert report.was_padded == false
	assert report.exceeded == true
	assert report.exec_elapsed >= 100 * time.millisecond
}

fn test_timed_call_report_invalid() {
	if _ := timed_call_report(time.Duration(0), fn () {}) {
		assert false
	}
	if _ := timed_call_report(-5 * time.millisecond, fn () {}) {
		assert false
	}
}

fn test_constant_time_eq_identical() {
	assert constant_time_eq([u8(1), 2, 3, 4, 5], [u8(1), 2, 3, 4, 5]) == true
}

fn test_constant_time_eq_different() {
	assert constant_time_eq([u8(1), 2, 3, 4, 5], [u8(1), 2, 3, 4, 6]) == false
}

fn test_constant_time_eq_first_byte_diff() {
	assert constant_time_eq([u8(0), 2, 3, 4, 5], [u8(1), 2, 3, 4, 5]) == false
}

fn test_constant_time_eq_different_lengths() {
	assert constant_time_eq([u8(1), 2, 3], [u8(1), 2, 3, 4]) == false
	assert constant_time_eq([u8(1), 2, 3, 4], [u8(1), 2, 3]) == false
}

fn test_constant_time_eq_empty() {
	assert constant_time_eq([]u8{}, []u8{}) == true
}

fn test_constant_time_eq_single_byte() {
	assert constant_time_eq([u8(42)], [u8(42)]) == true
	assert constant_time_eq([u8(42)], [u8(43)]) == false
}

fn test_constant_time_eq_strings_identical() {
	assert constant_time_eq_strings('hello_world', 'hello_world') == true
}

fn test_constant_time_eq_strings_different() {
	assert constant_time_eq_strings('hello', 'world') == false
}

fn test_constant_time_eq_strings_different_lengths() {
	assert constant_time_eq_strings('hello', 'hell') == false
	assert constant_time_eq_strings('hi', 'hello') == false
}

fn test_constant_time_eq_strings_empty() {
	assert constant_time_eq_strings('', '') == true
}

fn test_constant_time_eq_strings_similar() {
	assert constant_time_eq_strings('password1', 'password2') == false
	assert constant_time_eq_strings('abc', 'abd') == false
}

fn test_constant_time_eq_strings_case_sensitive() {
	assert constant_time_eq_strings('Hello', 'hello') == false
	assert constant_time_eq_strings('ABC', 'abc') == false
}

fn test_constant_time_eq_timing_consistency() {
	token := 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'.bytes()

	wrong_first := 'X1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'.bytes()
	wrong_last := 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5pX'.bytes()

	mut times_first := []i64{cap: 1000}
	mut times_last := []i64{cap: 1000}

	for _ in 0 .. 1000 {
		sw1 := time.new_stopwatch()
		_ := constant_time_eq(token, wrong_first)
		times_first << i64(sw1.elapsed())

		sw2 := time.new_stopwatch()
		_ := constant_time_eq(token, wrong_last)
		times_last << i64(sw2.elapsed())
	}

	mut avg_first := i64(0)
	mut avg_last := i64(0)
	for t in times_first {
		avg_first += t
	}
	for t in times_last {
		avg_last += t
	}
	avg_first /= 1000
	avg_last /= 1000

	diff := if avg_first > avg_last { avg_first - avg_last } else { avg_last - avg_first }
	max_acceptable := if avg_first > avg_last { avg_first } else { avg_last }
	assert diff < max_acceptable
}

fn test_timing_guard_password_check_simulation() {
	target := 200 * time.millisecond
	real_token := 'secure_token_12345'

	check_token := fn [real_token, target] (input string) bool {
		mut guard := new_timing_guard(target) or { return false }
		result := constant_time_eq_strings(input, real_token)
		guard.pad()
		return result
	}

	sw1 := time.new_stopwatch()
	r1 := check_token('x')
	t1 := sw1.elapsed()
	assert r1 == false
	assert t1 >= 180 * time.millisecond

	sw2 := time.new_stopwatch()
	r2 := check_token('secure_token_1234X')
	t2 := sw2.elapsed()
	assert r2 == false
	assert t2 >= 180 * time.millisecond

	sw3 := time.new_stopwatch()
	r3 := check_token('secure_token_12345')
	t3 := sw3.elapsed()
	assert r3 == true
	assert t3 >= 180 * time.millisecond

	diff_12 := if t1 > t2 { t1 - t2 } else { t2 - t1 }
	diff_13 := if t1 > t3 { t1 - t3 } else { t3 - t1 }
	assert diff_12 < 100 * time.millisecond
	assert diff_13 < 100 * time.millisecond
}

fn test_timed_call_with_result_workflow() {
	mut state := map[string]bool{}
	state['done'] = false

	report := timed_call_report(250 * time.millisecond, fn [mut state] () {
		time.sleep(30 * time.millisecond)
		state['done'] = true
	}) or { panic(err.str()) }

	assert state['done'] == true
	assert report.was_padded == true
	assert report.total == 250 * time.millisecond
}

fn test_hardened_i64_basic() {
	h := new_hardened_i64(42)
	assert h.get() or { panic(err.str()) } == 42
	assert h.verify() == true
}

fn test_hardened_i64_zero() {
	h := new_hardened_i64(0)
	assert h.get() or { panic(err.str()) } == 0
	assert h.verify() == true
}

fn test_hardened_i64_negative() {
	h := new_hardened_i64(-999)
	assert h.get() or { panic(err.str()) } == -999
}

fn test_hardened_i64_set() {
	mut h := new_hardened_i64(10)
	h.set(20)
	assert h.get() or { panic(err.str()) } == 20
	assert h.verify() == true
}

fn test_hardened_i64_corruption_val() {
	h := HardenedI64{
		val:   12345
		guard: ~i64(99999)
	}
	assert h.verify() == false
	if _ := h.get() {
		assert false
	}
}

fn test_hardened_i64_corruption_guard() {
	h := HardenedI64{
		val:   42
		guard: ~i64(42) ^ i64(1)
	}
	assert h.verify() == false
	if _ := h.get() {
		assert false
	}
}

fn test_hardened_i64_checked_add() {
	h := new_hardened_i64(100)
	h2 := h.checked_add(50) or { panic(err.str()) }
	assert h2.get() or { panic(err.str()) } == 150
}

fn test_hardened_i64_checked_add_overflow() {
	h := new_hardened_i64(max_i64_val)
	if _ := h.checked_add(1) {
		assert false
	}
}

fn test_hardened_i64_checked_sub() {
	h := new_hardened_i64(100)
	h2 := h.checked_sub(30) or { panic(err.str()) }
	assert h2.get() or { panic(err.str()) } == 70
}

fn test_hardened_i64_checked_sub_underflow() {
	h := new_hardened_i64(min_i64_val)
	if _ := h.checked_sub(1) {
		assert false
	}
}

fn test_hardened_i64_checked_mul() {
	h := new_hardened_i64(7)
	h2 := h.checked_mul(6) or { panic(err.str()) }
	assert h2.get() or { panic(err.str()) } == 42
}

fn test_hardened_i64_checked_div() {
	h := new_hardened_i64(100)
	h2 := h.checked_div(4) or { panic(err.str()) }
	assert h2.get() or { panic(err.str()) } == 25
}

fn test_hardened_i64_checked_div_zero() {
	h := new_hardened_i64(100)
	if _ := h.checked_div(0) {
		assert false
	}
}

fn test_hardened_i64_corrupted_add_rejected() {
	h := HardenedI64{
		val:   100
		guard: ~i64(999)
	}
	if _ := h.checked_add(1) {
		assert false
	}
}

fn test_hardened_i64_str() {
	h := new_hardened_i64(42)
	assert h.str() == '42 (hardened)'
}

fn test_hardened_i64_str_corrupted() {
	h := HardenedI64{
		val:   1
		guard: i64(0)
	}
	assert h.str() == 'CORRUPTED'
}

fn test_hardened_bool_true() {
	h := new_hardened_bool(true)
	assert h.get() or { panic(err.str()) } == true
	assert h.verify() == true
}

fn test_hardened_bool_false() {
	h := new_hardened_bool(false)
	assert h.get() or { panic(err.str()) } == false
	assert h.verify() == true
}

fn test_hardened_bool_set() {
	mut h := new_hardened_bool(false)
	h.set(true)
	assert h.get() or { panic(err.str()) } == true
	h.set(false)
	assert h.get() or { panic(err.str()) } == false
}

fn test_hardened_bool_corruption_guard() {
	h := HardenedBool{
		val:   hardened_true_pattern
		guard: u64(0)
	}
	assert h.verify() == false
	if _ := h.get() {
		assert false
	}
}

fn test_hardened_bool_corruption_val_bitflip() {
	h := HardenedBool{
		val:   hardened_true_pattern ^ u64(1)
		guard: ~(hardened_true_pattern ^ u64(1))
	}
	assert h.verify() == false
	if _ := h.get() {
		assert false
	}
}

fn test_hardened_bool_corruption_unknown_state() {
	h := HardenedBool{
		val:   u64(0x1234567890ABCDEF)
		guard: ~u64(0x1234567890ABCDEF)
	}
	if _ := h.get() {
		assert false
	}
}

fn test_hardened_bool_str() {
	h := new_hardened_bool(true)
	assert h.str() == 'true (hardened)'
	h2 := new_hardened_bool(false)
	assert h2.str() == 'false (hardened)'
}

fn test_hardened_bool_str_corrupted() {
	h := HardenedBool{
		val:   u64(0)
		guard: u64(0)
	}
	assert h.str() == 'CORRUPTED'
}

fn test_hardened_ranged_create_valid() {
	h := HardenedRangedInt.create(0, 100, 50) or { panic(err.str()) }
	assert h.value() or { panic(err.str()) } == 50
	assert h.min_val() or { panic(err.str()) } == 0
	assert h.max_val() or { panic(err.str()) } == 100
}

fn test_hardened_ranged_create_invalid_range() {
	if _ := HardenedRangedInt.create(100, 0, 50) {
		assert false
	}
}

fn test_hardened_ranged_create_out_of_range() {
	if _ := HardenedRangedInt.create(0, 100, 200) {
		assert false
	}
}

fn test_hardened_ranged_assign() {
	mut h := HardenedRangedInt.create(0, 100, 50) or { panic(err.str()) }
	h.assign(75) or { panic(err.str()) }
	assert h.value() or { panic(err.str()) } == 75
}

fn test_hardened_ranged_assign_invalid() {
	mut h := HardenedRangedInt.create(0, 100, 50) or { panic(err.str()) }
	mut failed := false
	h.assign(200) or { failed = true }
	assert failed
	assert h.value() or { panic(err.str()) } == 50
}

fn test_hardened_ranged_in_range() {
	h := HardenedRangedInt.create(0, 100, 50) or { panic(err.str()) }
	assert (h.in_range(50) or { panic(err.str()) }) == true
	assert (h.in_range(0) or { panic(err.str()) }) == true
	assert (h.in_range(100) or { panic(err.str()) }) == true
	assert (h.in_range(-1) or { panic(err.str()) }) == false
	assert (h.in_range(101) or { panic(err.str()) }) == false
}

fn test_hardened_ranged_checked_add() {
	h := HardenedRangedInt.create(-50, 50, 10) or { panic(err.str()) }
	h2 := h.checked_add(30) or { panic(err.str()) }
	assert h2.value() or { panic(err.str()) } == 40
}

fn test_hardened_ranged_checked_add_out_of_range() {
	h := HardenedRangedInt.create(0, 100, 90) or { panic(err.str()) }
	if _ := h.checked_add(20) {
		assert false
	}
}

fn test_hardened_ranged_checked_sub() {
	h := HardenedRangedInt.create(0, 100, 50) or { panic(err.str()) }
	h2 := h.checked_sub(30) or { panic(err.str()) }
	assert h2.value() or { panic(err.str()) } == 20
}

fn test_hardened_ranged_checked_mul() {
	h := HardenedRangedInt.create(-1000, 1000, 7) or { panic(err.str()) }
	h2 := h.checked_mul(10) or { panic(err.str()) }
	assert h2.value() or { panic(err.str()) } == 70
}

fn test_hardened_ranged_checked_div() {
	h := HardenedRangedInt.create(0, 1000, 100) or { panic(err.str()) }
	h2 := h.checked_div(4) or { panic(err.str()) }
	assert h2.value() or { panic(err.str()) } == 25
}

fn test_hardened_ranged_checked_div_zero() {
	h := HardenedRangedInt.create(0, 100, 50) or { panic(err.str()) }
	if _ := h.checked_div(0) {
		assert false
	}
}

fn test_hardened_ranged_corruption_value() {
	h := HardenedRangedInt{
		val:       50
		min:       0
		max:       100
		val_guard: ~i64(99)
		min_guard: ~i64(0)
		max_guard: ~i64(100)
	}
	if _ := h.value() {
		assert false
	}
}

fn test_hardened_ranged_corruption_min() {
	h := HardenedRangedInt{
		val:       50
		min:       0
		max:       100
		val_guard: ~i64(50)
		min_guard: ~i64(999)
		max_guard: ~i64(100)
	}
	if _ := h.value() {
		assert false
	}
}

fn test_hardened_ranged_corruption_max() {
	h := HardenedRangedInt{
		val:       50
		min:       0
		max:       100
		val_guard: ~i64(50)
		min_guard: ~i64(0)
		max_guard: ~i64(999)
	}
	if _ := h.value() {
		assert false
	}
}

fn test_hardened_ranged_corrupted_blocks_add() {
	h := HardenedRangedInt{
		val:       50
		min:       0
		max:       100
		val_guard: ~i64(42)
		min_guard: ~i64(0)
		max_guard: ~i64(100)
	}
	if _ := h.checked_add(1) {
		assert false
	}
}

fn test_hardened_ranged_corrupted_blocks_sub() {
	h := HardenedRangedInt{
		val:       50
		min:       0
		max:       100
		val_guard: ~i64(50)
		min_guard: ~i64(1)
		max_guard: ~i64(100)
	}
	if _ := h.checked_sub(1) {
		assert false
	}
}

fn test_hardened_ranged_corrupted_blocks_assign() {
	mut h := HardenedRangedInt{
		val:       50
		min:       0
		max:       100
		val_guard: ~i64(50)
		min_guard: ~i64(0)
		max_guard: ~i64(77)
	}
	mut failed := false
	h.assign(60) or { failed = true }
	assert failed
}

fn test_hardened_ranged_str() {
	h := HardenedRangedInt.create(0, 100, 50) or { panic(err.str()) }
	assert h.str() == '50 in [0..100] (hardened)'
}

fn test_hardened_ranged_str_corrupted() {
	h := HardenedRangedInt{
		val:       50
		min:       0
		max:       100
		val_guard: i64(0)
		min_guard: ~i64(0)
		max_guard: ~i64(100)
	}
	assert h.str() == 'CORRUPTED'
}

fn test_safe_index_mask_valid_indices() {
	assert safe_index_mask(0, 10) == 0
	assert safe_index_mask(1, 10) == 1
	assert safe_index_mask(5, 10) == 5
	assert safe_index_mask(9, 10) == 9
}

fn test_safe_index_mask_at_boundary() {
	assert safe_index_mask(10, 10) == 0
	assert safe_index_mask(99, 100) == 99
	assert safe_index_mask(100, 100) == 0
}

fn test_safe_index_mask_out_of_bounds() {
	assert safe_index_mask(10, 5) == 0
	assert safe_index_mask(100, 10) == 0
	assert safe_index_mask(999, 10) == 0
}

fn test_safe_index_mask_negative() {
	assert safe_index_mask(-1, 10) == 0
	assert safe_index_mask(-100, 10) == 0
	assert safe_index_mask(-999999, 10) == 0
}

fn test_safe_index_mask_zero_length() {
	assert safe_index_mask(0, 0) == 0
	assert safe_index_mask(5, 0) == 0
}

fn test_safe_index_mask_single_element() {
	assert safe_index_mask(0, 1) == 0
	assert safe_index_mask(1, 1) == 0
	assert safe_index_mask(-1, 1) == 0
}

fn test_safe_index_mask_64_valid() {
	assert safe_index_mask_64(0, 10) == 0
	assert safe_index_mask_64(5, 10) == 5
	assert safe_index_mask_64(9, 10) == 9
}

fn test_safe_index_mask_64_invalid() {
	assert safe_index_mask_64(10, 10) == 0
	assert safe_index_mask_64(100, 10) == 0
	assert safe_index_mask_64(-1, 10) == 0
}

fn test_hardened_workflow() {
	mut balance := HardenedRangedInt.create(0, 99999999, 100000) or { panic(err.str()) }
	mut is_admin := new_hardened_bool(false)
	mut tx_count := new_hardened_i64(0)
	
	balance = balance.checked_add(50000) or { panic(err.str()) }
	tx_count = tx_count.checked_add(1) or { panic(err.str()) }
	assert balance.value() or { panic(err.str()) } == 150000
	assert tx_count.get() or { panic(err.str()) } == 1
	
	balance = balance.checked_sub(30000) or { panic(err.str()) }
	tx_count = tx_count.checked_add(1) or { panic(err.str()) }
	assert balance.value() or { panic(err.str()) } == 120000
	assert tx_count.get() or { panic(err.str()) } == 2
	
	assert is_admin.get() or { panic(err.str()) } == false
	is_admin.set(true)
	assert is_admin.get() or { panic(err.str()) } == true
	
	assert is_admin.verify() == true
	assert tx_count.verify() == true
}