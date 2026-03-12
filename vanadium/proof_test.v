module vanadium

fn test_new_prover() {
	p := new_prover('basic')
	assert p.name == 'basic'
	assert p.max_cases == vanadium.max_proof_cases
	assert p.results.len == 0
}

fn test_new_prover_with_limit() {
	p := new_prover_with_limit('limited', 42)
	assert p.name == 'limited'
	assert p.max_cases == 42
}

fn test_prove_for_range_pass() {
	mut p := new_prover('test')
	p.prove_for_range('x >= 0', 0, 50, fn (x i64) bool {
		return x >= 0
	})
	assert p.all_passed()
	$if debug {
		assert p.results.len == 1
		assert p.results[0].passed
		assert p.results[0].cases == 51
		assert p.passed_count() == 1
		assert p.failed_count() == 0
	}
}

fn test_prove_for_range_fail() {
	mut p := new_prover('test')
	p.prove_for_range('x < 10', 0, 20, fn (x i64) bool {
		return x < 10
	})
	$if debug {
		assert p.results.len == 1
		assert !p.results[0].passed
		assert p.results[0].detail.contains('counterexample: 10')
	}
}

fn test_prove_for_range_invalid_range() {
	mut p := new_prover('test')
	p.prove_for_range('bad range', 10, 5, fn (x i64) bool {
		return true
	})
	$if debug {
		assert p.results.len == 1
		assert !p.results[0].passed
		assert p.results[0].detail.contains('invalid range')
	}
}

fn test_prove_for_range_single_value() {
	mut p := new_prover('test')
	p.prove_for_range('single', 7, 7, fn (x i64) bool {
		return x == 7
	})
	assert p.all_passed()
	$if debug {
		assert p.results[0].cases == 1
	}
}

fn test_prove_for_range_max_cases_exceeded() {
	mut p := new_prover_with_limit('limited', 5)
	p.prove_for_range('too many', 0, 100, fn (x i64) bool {
		return true
	})
	$if debug {
		assert p.results.len == 1
		assert !p.results[0].passed
		assert p.results[0].detail.contains('exceeded')
	}
}

fn test_prove_for_pairs_pass() {
	mut p := new_prover('test')
	p.prove_for_pairs('AM-GM', 0, 10, fn (x i64, y i64) bool {
		return 2 * x * y <= x * x + y * y
	})
	assert p.all_passed()
	$if debug {
		assert p.results[0].passed
		assert p.results[0].cases == 121
	}
}

fn test_prove_for_pairs_fail() {
	mut p := new_prover('test')
	p.prove_for_pairs('always equal', 0, 3, fn (x i64, y i64) bool {
		return x == y
	})
	$if debug {
		assert !p.results[0].passed
		assert p.results[0].detail.contains('counterexample')
	}
}

fn test_prove_for_pairs_invalid_range() {
	mut p := new_prover('test')
	p.prove_for_pairs('bad', 5, 0, fn (x i64, y i64) bool {
		return true
	})
	$if debug {
		assert !p.results[0].passed
	}
}

fn test_prove_exists_found() {
	mut p := new_prover('test')
	p.prove_exists('find even', 1, 10, fn (x i64) bool {
		return x % 2 == 0
	})
	$if debug {
		assert p.results[0].passed
		assert p.results[0].detail.contains('witness: 2')
	}
}

fn test_prove_exists_not_found() {
	mut p := new_prover('test')
	p.prove_exists('negative in positives', 1, 50, fn (x i64) bool {
		return x < 0
	})
	$if debug {
		assert !p.results[0].passed
		assert p.results[0].detail.contains('no witness')
	}
}

fn test_prove_exists_first_element() {
	mut p := new_prover('test')
	p.prove_exists('find 0', 0, 100, fn (x i64) bool {
		return x == 0
	})
	$if debug {
		assert p.results[0].passed
		assert p.results[0].cases == 1
	}
}

fn test_prove_by_samples_pass() {
	mut p := new_prover('test')
	p.prove_by_samples('square positive', 1, 1_000_000, 100, fn (x i64) bool {
		return x * x > 0
	})
	assert p.all_passed()
	$if debug {
		assert p.results[0].passed
		assert p.results[0].cases == 100
	}
}

fn test_prove_by_samples_fail_at_lower() {
	mut p := new_prover('test')
	p.prove_by_samples('never zero', 0, 100, 50, fn (x i64) bool {
		return x != 0
	})
	$if debug {
		assert !p.results[0].passed
		assert p.results[0].detail.contains('lower bound')
	}
}

fn test_prove_by_samples_invalid() {
	mut p := new_prover('test')
	p.prove_by_samples('bad count', 0, 10, 0, fn (x i64) bool {
		return true
	})
	$if debug {
		assert !p.results[0].passed
		assert p.results[0].detail.contains('invalid')
	}
}

fn test_prove_ranged() {
	mut p := new_prover('test')
	r := RangedIntP{min: 0, max: 20}
	p.prove_ranged('in range', r, fn (x i64) bool {
		return x >= 0 && x <= 20
	})
	assert p.all_passed()
	$if debug {
		assert p.results[0].passed
		assert p.results[0].cases == 21
	}
}

fn test_prove_commutative_pass() {
	mut p := new_prover('test')
	p.prove_commutative('add commutes', -10, 10, fn (a i64, b i64) i64 {
		return a + b
	})
	assert p.all_passed()
	$if debug {
		assert p.results[0].passed
	}
}

fn test_prove_commutative_fail() {
	mut p := new_prover('test')
	p.prove_commutative('sub commutes', 0, 5, fn (a i64, b i64) i64 {
		return a - b
	})
	$if debug {
		assert !p.results[0].passed
		assert p.results[0].detail.contains('!=')
	}
}

fn test_prove_commutative_mul() {
	mut p := new_prover('test')
	p.prove_commutative('mul commutes', -5, 5, fn (a i64, b i64) i64 {
		return a * b
	})
	assert p.all_passed()
}

fn test_prove_associative_pass() {
	mut p := new_prover('test')
	p.prove_associative('add assoc', -3, 3, fn (a i64, b i64) i64 {
		return a + b
	})
	assert p.all_passed()
	$if debug {
		assert p.results[0].passed
		assert p.results[0].cases == 343
	}
}

fn test_prove_associative_fail() {
	mut p := new_prover('test')
	p.prove_associative('sub assoc', 0, 2, fn (a i64, b i64) i64 {
		return a - b
	})
	$if debug {
		assert !p.results[0].passed
	}
}

fn test_prove_monotonic_pass() {
	mut p := new_prover('test')
	p.prove_monotonic('double', 0, 100, fn (x i64) i64 {
		return 2 * x
	})
	assert p.all_passed()
	$if debug {
		assert p.results[0].passed
	}
}

fn test_prove_monotonic_fail() {
	mut p := new_prover('test')
	p.prove_monotonic('negate', 0, 10, fn (x i64) i64 {
		return -x
	})
	$if debug {
		assert !p.results[0].passed
		assert p.results[0].detail.contains('<')
	}
}

fn test_prove_monotonic_single_value() {
	mut p := new_prover('test')
	p.prove_monotonic('trivial', 5, 5, fn (x i64) i64 {
		return x
	})
	assert p.all_passed()
	$if debug {
		assert p.results[0].passed
		assert p.results[0].detail.contains('trivially')
	}
}

fn test_prove_monotonic_identity() {
	mut p := new_prover('test')
	p.prove_monotonic('identity', -50, 50, fn (x i64) i64 {
		return x
	})
	assert p.all_passed()
}

fn test_prove_idempotent_pass() {
	mut p := new_prover('test')
	p.prove_idempotent('abs', -50, 50, fn (x i64) i64 {
		if x < 0 {
			return -x
		}
		return x
	})
	assert p.all_passed()
	$if debug {
		assert p.results[0].passed
	}
}

fn test_prove_idempotent_fail() {
	mut p := new_prover('test')
	p.prove_idempotent('increment', 0, 5, fn (x i64) i64 {
		return x + 1
	})
	$if debug {
		assert !p.results[0].passed
		assert p.results[0].detail.contains('f(f(')
	}
}

fn test_prove_idempotent_clamp() {
	mut p := new_prover('test')
	p.prove_idempotent('clamp 0..10', -20, 30, fn (x i64) i64 {
		if x < 0 {
			return 0
		}
		if x > 10 {
			return 10
		}
		return x
	})
	assert p.all_passed()
}

fn test_prove_involution_pass() {
	mut p := new_prover('test')
	p.prove_involution('negate', -100, 100, fn (x i64) i64 {
		return -x
	})
	assert p.all_passed()
	$if debug {
		assert p.results[0].passed
	}
}

fn test_prove_involution_fail() {
	mut p := new_prover('test')
	p.prove_involution('double', 1, 10, fn (x i64) i64 {
		return 2 * x
	})
	$if debug {
		assert !p.results[0].passed
	}
}

fn test_prove_involution_identity() {
	mut p := new_prover('test')
	p.prove_involution('identity', -20, 20, fn (x i64) i64 {
		return x
	})
	assert p.all_passed()
}

fn test_prove_injective_pass() {
	mut p := new_prover('test')
	p.prove_injective('double', 0, 50, fn (x i64) i64 {
		return 2 * x
	})
	assert p.all_passed()
	$if debug {
		assert p.results[0].passed
	}
}

fn test_prove_injective_fail() {
	mut p := new_prover('test')
	p.prove_injective('abs', -10, 10, fn (x i64) i64 {
		if x < 0 {
			return -x
		}
		return x
	})
	$if debug {
		assert !p.results[0].passed
		assert p.results[0].detail.contains('==')
	}
}

fn test_report_output() {
	mut p := new_prover('report test')
	p.prove_for_range('always true', 0, 3, fn (x i64) bool {
		return true
	})
	r := p.report()
	$if debug {
		assert r.contains('report test')
		assert r.contains('PROVEN')
		assert r.contains('always true')
		assert r.contains('Summary')
	} $else {
		assert r == ''
	}
}

fn test_multiple_proofs_mixed() {
	mut p := new_prover('multi')
	p.prove_for_range('pass1', 0, 5, fn (x i64) bool {
		return true
	})
	p.prove_for_range('pass2', 0, 5, fn (x i64) bool {
		return x >= 0
	})
	p.prove_for_range('fail1', 0, 10, fn (x i64) bool {
		return x < 5
	})
	$if debug {
		assert p.results.len == 3
		assert p.passed_count() == 2
		assert p.failed_count() == 1
		assert !p.all_passed()
	}
}

fn test_all_passed_empty() {
	p := new_prover('empty')
	$if debug {
		assert !p.all_passed()
	} $else {
		assert p.all_passed()
	}
}

fn test_loop_proof_pass() {
	mut lp := new_loop_proof('countdown')
	mut n := i64(5)
	for n > 0 {
		lp.iteration()
		lp.check_invariant(n > 0, 'n must be positive') or {
			assert false
			break
		}
		lp.check_variant(n) or {
			assert false
			break
		}
		n--
	}
	result := lp.finish()
	assert result.passed
	$if debug {
		assert result.cases == 5
		assert result.detail.contains('5 iterations')
	}
}

fn test_loop_proof_invariant_violation() {
	mut lp := new_loop_proof('bad loop')
	mut hit_error := false
	mut n := i64(3)
	for n > -2 {
		lp.iteration()
		lp.check_invariant(n > 0, 'n must be positive') or {
			hit_error = true
			break
		}
		n--
	}
	result := lp.finish()
	$if debug {
		assert hit_error
		assert !result.passed
		assert result.detail.contains('invariant violated')
	}
}

fn test_loop_proof_variant_not_decreasing() {
	mut lp := new_loop_proof('increasing variant')
	mut hit_error := false
	for i in 0 .. 5 {
		lp.iteration()
		lp.check_variant(i64(i)) or {
			hit_error = true
			break
		}
	}
	result := lp.finish()
	$if debug {
		assert hit_error
		assert !result.passed
		assert result.detail.contains('variant not decreasing')
	}
}

fn test_loop_proof_variant_negative() {
	mut lp := new_loop_proof('negative variant')
	mut hit_error := false
	lp.iteration()
	lp.check_variant(-1) or {
		hit_error = true
	}
	result := lp.finish()
	$if debug {
		assert hit_error
		assert !result.passed
		assert result.detail.contains('variant negative')
	}
}

fn test_loop_proof_finish_release() {
	lp := new_loop_proof('empty')
	result := lp.finish()
	assert result.passed
}

fn test_sm_valid_steps() {
	mut sm := new_state_machine('traffic', 0)
	sm.add_state(0, 'green')
	sm.add_state(1, 'yellow')
	sm.add_state(2, 'red')
	sm.add_transition(0, 1)
	sm.add_transition(1, 2)
	sm.add_transition(2, 0)

	sm.step(1) or { assert false }
	assert sm.current == 1
	sm.step(2) or { assert false }
	assert sm.current == 2
	sm.step(0) or { assert false }
	assert sm.current == 0

	assert sm.trace == [0, 1, 2, 0]
}

fn test_sm_invalid_step() {
	mut sm := new_state_machine('test', 0)
	sm.add_state(0, 'A')
	sm.add_state(1, 'B')
	sm.add_state(2, 'C')
	sm.add_transition(0, 1)

	sm.step(2) or {
		assert err.msg().contains('invalid transition')
		assert err.msg().contains('A')
		assert err.msg().contains('C')
		return
	}
	assert false
}

fn test_sm_state_name_known() {
	mut sm := new_state_machine('test', 0)
	sm.add_state(0, 'start')
	sm.add_state(1, 'end')
	assert sm.state_name(0) == 'start'
	assert sm.state_name(1) == 'end'
}

fn test_sm_state_name_unknown() {
	sm := new_state_machine('test', 0)
	assert sm.state_name(99) == '99'
}

fn test_sm_verify_trace_pass() {
	mut sm := new_state_machine('test', 0)
	sm.add_transition(0, 1)
	sm.add_transition(1, 2)
	sm.step(1) or { assert false }
	sm.step(2) or { assert false }

	sm.verify_trace([0, 1, 2]) or {
		$if debug {
			assert false
		}
	}
}

fn test_sm_verify_trace_mismatch() {
	mut sm := new_state_machine('test', 0)
	sm.add_transition(0, 1)
	sm.step(1) or { assert false }

	$if debug {
		sm.verify_trace([0, 2]) or {
			assert err.msg().contains('trace mismatch')
			return
		}
		assert false
	}
}

fn test_sm_verify_trace_length_mismatch() {
	mut sm := new_state_machine('test', 0)
	$if debug {
		sm.verify_trace([0, 1, 2]) or {
			assert err.msg().contains('trace mismatch')
			return
		}
		assert false
	}
}

fn test_sm_verify_reachable() {
	mut sm := new_state_machine('test', 0)
	sm.add_state(0, 'A')
	sm.add_state(1, 'B')
	sm.add_state(2, 'C')
	sm.add_state(3, 'D')
	sm.add_transition(0, 1)
	sm.add_transition(1, 2)

	$if debug {
		assert sm.verify_reachable(2)
		assert !sm.verify_reachable(3)
		assert !sm.verify_reachable(99)
	} $else {
		assert sm.verify_reachable(99)
	}
}

fn test_sm_verify_no_deadlock_pass() {
	mut sm := new_state_machine('test', 0)
	sm.add_state(0, 'A')
	sm.add_state(1, 'B')
	sm.add_transition(0, 1)
	sm.add_transition(1, 0)
	sm.verify_no_deadlock() or {
		$if debug {
			assert false
		}
	}
}

fn test_sm_verify_no_deadlock_detected() {
	mut sm := new_state_machine('test', 0)
	sm.add_state(0, 'A')
	sm.add_state(1, 'sink')
	sm.add_transition(0, 1)

	$if debug {
		sm.verify_no_deadlock() or {
			assert err.msg().contains('deadlock')
			assert err.msg().contains('sink')
			return
		}
		assert false
	}
}

fn test_sm_self_loop() {
	mut sm := new_state_machine('self', 0)
	sm.add_state(0, 'idle')
	sm.add_transition(0, 0)
	sm.step(0) or { assert false }
	sm.step(0) or { assert false }
	assert sm.trace == [0, 0, 0]
}

fn test_guard_pass() {
	guard(true, 'ok') or { assert false }
}

fn test_guard_fail() {
	guard(false, 'bad') or {
		assert err.msg().contains('guard failed')
		return
	}
	assert false
}


fn test_ensure_positive_ok() {
	r := ensure_positive(5) or {
		assert false
		return
	}
	assert r == 5
}

fn test_ensure_positive_zero_fails() {
	ensure_positive(0) or {
		assert err.msg().contains('expected positive')
		return
	}
	assert false
}

fn test_ensure_positive_negative_fails() {
	ensure_positive(-3) or { return }
	assert false
}

fn test_ensure_non_negative_ok() {
	v0 := ensure_non_negative(0) or {
		assert false
		return
	}
	assert v0 == 0
	v5 := ensure_non_negative(5) or {
		assert false
		return
	}
	assert v5 == 5
}

fn test_ensure_non_negative_fail() {
	ensure_non_negative(-1) or {
		assert err.msg().contains('expected non-negative')
		return
	}
	assert false
}

fn test_ensure_in_range_ok() {
	r := ensure_in_range(5, 0, 10) or {
		assert false
		return
	}
	assert r == 5
}

fn test_ensure_in_range_at_bounds() {
	lo := ensure_in_range(0, 0, 10) or {
		assert false
		return
	}
	assert lo == 0
	hi := ensure_in_range(10, 0, 10) or {
		assert false
		return
	}
	assert hi == 10
}

fn test_ensure_in_range_below() {
	ensure_in_range(-1, 0, 10) or {
		assert err.msg().contains('out of range')
		return
	}
	assert false
}

fn test_ensure_in_range_above() {
	ensure_in_range(11, 0, 10) or {
		assert err.msg().contains('out of range')
		return
	}
	assert false
}

fn test_clamp_within() {
	assert clamp(5, 0, 10) == 5
}

fn test_clamp_below() {
	assert clamp(-5, 0, 10) == 0
}

fn test_clamp_above() {
	assert clamp(15, 0, 10) == 10
}

fn test_clamp_at_bounds() {
	assert clamp(0, 0, 10) == 0
	assert clamp(10, 0, 10) == 10
}

fn test_in_range_true() {
	assert in_range(5, 0, 10)
	assert in_range(0, 0, 10)
	assert in_range(10, 0, 10)
}

fn test_in_range_false() {
	assert !in_range(-1, 0, 10)
	assert !in_range(11, 0, 10)
}

fn test_safe_cast_u8_ok() {
	r := safe_cast_u8(0) or {
		assert false
		return
	}
	assert r == 0

	r2 := safe_cast_u8(255) or {
		assert false
		return
	}
	assert r2 == 255
}

fn test_safe_cast_u8_overflow() {
	safe_cast_u8(256) or { return }
	assert false
}

fn test_safe_cast_u8_negative() {
	safe_cast_u8(-1) or { return }
	assert false
}

fn test_safe_cast_i16_ok() {
	r := safe_cast_i16(1000) or {
		assert false
		return
	}
	assert r == 1000
}

fn test_safe_cast_i16_overflow() {
	safe_cast_i16(40000) or { return }
	assert false
}

fn test_safe_cast_i32_ok() {
	r := safe_cast_i32(100000) or {
		assert false
		return
	}
	assert r == 100000
}

fn test_safe_cast_i32_overflow() {
	safe_cast_i32(3_000_000_000) or { return }
	assert false
}