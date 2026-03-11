//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <https://www.gnu.org/licenses/>.

// v -enable-globals -prod -gc boehm -prealloc -skip-unused -d no_backtrace -d no_debug -cc clang -cflags "-O3 -flto -fPIE -fstack-protector-all -fstack-clash-protection -D_FORTIFY_SOURCE=3 -fno-ident -fno-common -fwrapv -ftrivial-auto-var-init=zero -fvisibility=hidden -Wformat -Wformat-security -Werror=format-security" -ldflags "-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code -Wl,--gc-sections -Wl,--icf=all -Wl,--build-id=none" mimicfs.v -o mimicfs && strip --strip-all --remove-section=.comment --remove-section=.note --remove-section=.gnu.version --remove-section=.note.ABI-tag --remove-section=.note.gnu.build-id --remove-section=.note.android.ident --remove-section=.eh_frame --remove-section=.eh_frame_hdr mimicfs

import os
import time
import term
import math
import term.ui as tui
import crypto.sha256
import rand

@[packed; minify]
struct PwGuard {
mut:
	files [][]u8
}

@[inline; unsafe; _cold]
fn (mut g PwGuard) free() {
	for mut arr in g.files {
		unsafe { arr.free() }
	}
	unsafe { g.files.free() }
}

@[inline; must_use; direct_array_access; _cold]
fn PwGuard.new() PwGuard {
	mut guard := PwGuard{ files: [] []u8{cap: 4} }
	for _ in 0 .. 3 {
		mut data := []u8{len: 4096}
		for i in 0 .. 256 { data[i] = u8(i) }
		for i in 256 .. data.len { data[i] = u8(rand.intn(256) or { 0 }) }
		rand.shuffle(mut data) or {}
		guard.files << data
	}
	return guard
}

@[inline; must_use; _hot]
fn (g PwGuard) encode(password string) !string {
	mut pointers := []string{cap: password.len}
	for b in password.bytes() {
		mut found := false
		sf := rand.intn(g.files.len) or { 0 }
		for attempt in 0 .. g.files.len {
			fi := (sf + attempt) % g.files.len
			so := rand.intn(g.files[fi].len) or { 0 }
			for j in 0 .. g.files[fi].len {
				offset := (so + j) % g.files[fi].len
				if g.files[fi][offset] == b {
					pointers << '${fi}:${offset}'
					found = true
					break
				}
			}
			if found { break }
		}
		if _unlikely_(!found) { return error('byte ${b} not found') }
	}
	return pointers.join(',')
}

@[inline; must_use; _hot]
fn (g PwGuard) decode(pointer_str string) !string {
	parts := pointer_str.split(',')
	mut pw := []u8{cap: parts.len}
	for part in parts {
		t := part.split(':')
		if _unlikely_(t.len != 2) { return error('bad format') }
		fi := t[0].int()
		off := t[1].int()
		if _unlikely_(fi >= g.files.len) || off >= g.files[fi].len {
			return error('bad index')
		}
		pw << g.files[fi][off]
	}
	return pw.bytestr()
}

@[inline; _hot]
fn send_notification(title string, message string) {
	os.execute("su -lp 2000 -c \"cmd notification post -S bigtext -t '$title' 'Security_Monitor' '$message'\"")
}

@[inline; must_use; _hot]
fn get_ppid(pid int) int {
	lines := os.read_lines('/proc/$pid/status') or { return 0 }
	for line in lines {
		if line.starts_with('PPid:') {
			parts := line.split(':')
			if _likely_(parts.len > 1) {
				return parts[1].trim_space().int()
			}
		}
	}
	return 0
}

@[inline; must_use; direct_array_access; _hot]
fn get_gps_interrupt_sum() i64 {
	mut total := i64(0)
	lines := os.read_lines('/proc/interrupts') or { return 0 }
	for line in lines {
		if line.contains('gps') {
			fields := line.fields()
			for i in 1 .. fields.len {
				val := fields[i].i64()
				if val > 0 { total += val }
			}
		}
	}
	return total
}

@[inline; _cold]
fn disable_sim_toolkit() {
	pkgs := ['com.android.stk', 'com.google.android.stk', 'com.samsung.android.stk']
	for pkg in pkgs {
		os.execute("su -c \"pm disable-user --user 0 $pkg\"")
	}
}

@[inline; direct_array_access; _cold]
fn despy() {
	println('${term.cyan('DeSpy 1.4')}')

	if _unlikely_(os.args.len > 1 && os.args[1] == 'r') {
		os.execute("su -c \"echo 'musb-hdrc' > /config/usb_gadget/g1/UDC\"")
		os.execute("setprop sys.usb.config mtp,adb")
		os.execute("setprop sys.usb.state mtp,adb")
		println("${term.green('✔')} [${get_time_str()}] USB Port Restored. Monitoring Stopped.")
		return
	}

	os.execute("su -c \"echo '' > /config/usb_gadget/g1/UDC\"")
	os.execute("setprop sys.usb.config none")
	os.execute("setprop sys.usb.state none")

	disable_sim_toolkit()

	mut camera_paths := []string{}
	mut mic_status_paths := []string{}
	camera_keywords := ['vcam', 'camera', 'vfe', 'avdd', 'ov', 'imx']
	reg_base := '/sys/class/regulator'

	if _likely_(os.exists(reg_base)) {
		reg_dirs := os.ls(reg_base) or { []string{} }
		for dir in reg_dirs {
			name_file := reg_base + '/' + dir + '/name'
			if os.exists(name_file) {
				name := os.read_file(name_file) or { '' }.to_lower()
				for kw in camera_keywords {
					if name.contains(kw) {
						u_path := reg_base + '/' + dir + '/num_users'
						if os.exists(u_path) { camera_paths << u_path; break }
					}
				}
			}
		}
	}

	asound_base := '/proc/asound'
	if _likely_(os.exists(asound_base)) {
		cards := os.ls(asound_base) or { []string{} }
		for card in cards {
			if card.starts_with('card') {
				card_path := asound_base + '/' + card
				pcms := os.ls(card_path) or { []string{} }
				for pcm in pcms {
					if pcm.ends_with('c') {
						sub_dirs := os.ls(card_path + '/' + pcm) or { []string{} }
						for sub in sub_dirs {
							if sub.starts_with('sub') {
								status_file := card_path + '/' + pcm + '/' + sub + '/status'
								if _likely_(os.exists(status_file)) { mic_status_paths << status_file }
							}
						}
					}
				}
			}
		}
	}

	println('${term.yellow('⚠')} [${get_time_str()}] DeSpy Active: USB Port KILLED & Monitoring Started.')

	mut last_cam_state := false
	mut last_mic_state := false
	mut last_gps_state := false
	mut last_gps_sum := get_gps_interrupt_sum()
	mut gps_stagnant_count := 0
	my_pid := os.getpid()

	for {
		pids := os.ls('/proc') or { []string{} }
		mut rild_pids := []int{}
		ts := get_time_str()

		for pid_s in pids {
			if !pid_s.is_int() { continue }
			pid_i := pid_s.int()
			if pid_i == my_pid { continue }

			cmdline := os.read_file('/proc/$pid_s/cmdline') or { '' }
			if cmdline.contains('rild') || cmdline.contains('radio') || cmdline.contains('com.android.phone') {
				rild_pids << pid_i
			}
		}

		for pid_s in pids {
			if !pid_s.is_int() { continue }
			pid_i := pid_s.int()
			if pid_i <= 1000 || pid_i == my_pid { continue }

			stat_path := '/proc/$pid_s/status'
			if _likely_(os.exists(stat_path)) {
				uid_data := os.read_file(stat_path) or { '' }

				ppid := get_ppid(pid_i)
				if ppid in rild_pids {
					exe_path := os.execute('readlink /proc/$pid_s/exe').output.trim_space()
					if exe_path.ends_with('/sh') ||
					   exe_path.ends_with('/bash') ||
					   exe_path.contains('curl') ||
					   exe_path.contains('wget') ||
					   exe_path.contains('busybox') ||
					   exe_path.contains('/data/local/tmp') {

						println('${term.red('☠')} [$ts] CRITICAL: Baseband Exploit Detected! RIL spawned: $exe_path')
						os.execute('kill -9 $pid_i')
						os.execute('kill -9 $ppid')
						send_notification('BASEBAND ATTACK', 'RIL process killed due to exploit attempt.')
					}
				}

				if uid_data.contains('Uid:\t0') || uid_data.contains('Uid: 0') {
					mut is_vulnerable := false
					maps_path := '/proc/$pid_s/maps'
					if os.exists(maps_path) {
						maps_lines := os.read_lines(maps_path) or { []string{} }
						for line in maps_lines {
							parts := line.split(' ').filter(it != '')
							if parts.len < 5 { continue }
							
							perms := parts[1]
							
							if perms.contains('x') {
								mut path := ''
								if parts.len >= 6 {
									path = parts[5]
								}
								
								if perms.contains('w') {
									is_vulnerable = true
									break
								}
								
								if path == '' || (path.starts_with('[') && path != '[vdso]' && path != '[vsyscall]') {
									is_vulnerable = true
									break
								}
								
								if path != '' && !path.starts_with('[') {
									if path.contains('/tmp/') || path.contains('/data/local/tmp/') {
										is_vulnerable = true
										break
									}
								}
							}
						}
					}

					exe_res := os.execute('readlink /proc/$pid_s/exe')
					exe_path := exe_res.output.trim_space()

					if exe_path.len > 0 {
						is_trusted := exe_path.starts_with('/system/') ||
									  exe_path.starts_with('/vendor/') ||
									  exe_path.starts_with('/apex/') ||
									  exe_path.starts_with('/odm/') ||
									  exe_path.starts_with('/product/') ||
									  exe_path.starts_with('/system_ext/') ||
									  exe_path.starts_with('/data/app/') ||
									  exe_path.starts_with('/data/adb/') ||
									  exe_path.starts_with('/debug_ramdisk/') ||
									  exe_path.starts_with('/dev/') ||
									  exe_path.starts_with('/data/data/com.termux/files/')

						if _unlikely_(!is_trusted || (is_vulnerable && !exe_path.starts_with('/system/'))) {
							os.execute('kill -9 $pid_i')
							reason := if is_vulnerable { 'Memory Integrity Violation' } else { 'Untrusted Root' }
							msg := '$reason: $exe_path (PID: $pid_i)'
							println('${term.red('✘')} [$ts] $msg')
							send_notification('Security Alert', msg)
						}
					}
				}
			}
		}

		mut cam_active := false
		for cp in camera_paths {
			if os.read_file(cp) or { '0' }.trim_space().int() > 0 { cam_active = true; break }
		}

		mut mic_active := false
		for mp in mic_status_paths {
			if (os.read_file(mp) or { '' }).contains('RUNNING') { mic_active = true; break }
		}

		cur_gps_sum := get_gps_interrupt_sum()
		mut gps_active := false
		if cur_gps_sum > last_gps_sum {
			gps_active = true
			gps_stagnant_count = 0
			last_gps_sum = cur_gps_sum
		} else {
			gps_stagnant_count++
			if gps_stagnant_count < 3 { gps_active = last_gps_state }
		}

		if cam_active != last_cam_state {
			if cam_active {
				send_notification('Alert', 'Camera sensor active.')
				println('${term.yellow('⚠')} [$ts] Camera active.')
			}
			last_cam_state = cam_active
		}
		if mic_active != last_mic_state {
			if mic_active {
				send_notification('Alert', 'Microphone sensor active.')
				println('${term.yellow('⚠')} [$ts] Microphone active.')
			}
			last_mic_state = mic_active
		}
		if gps_active != last_gps_state {
			if gps_active {
				send_notification('Alert', 'GPS hardware active.')
				println('${term.yellow('⚠')} [$ts] GPS activity.')
			}
			last_gps_state = gps_active
		}

		time.sleep(3000 * time.millisecond)
	}
}

@[inline; must_use; _hot]
fn get_time_str() string {
	t := time.now()
	return '${t.hour:02}:${t.minute:02}:${t.second:02}'
}

@[inline; direct_array_access; _cold]
fn manage_snapshot_protection(enable bool) {
	targets := [
		'/data/system_ce/0/snapshots',
		'/data/system_ce/0/usagestats',
		'/data/system/dropbox',
		'/data/tombstones',
		'/data/anr',
		'/data/misc/logd',
		'/data/bugreports',
		'/data/log',
		'/data/vendor/log',
		'/data/misc/recovery',
		'/data/system_ce/0/recent_images',
		'/data/system_ce/0/recent_tasks',
		'/data/system/recent_tasks',
		'/data/misc/wmtrace',
		'/data/misc/perfetto-traces',
		'/data/local/traces',
		'/data/system/graphicsstats',
		'/data/system/procstats',
		'/data/system/netstats',
		'/data/system_ce/0/notification_history',
		'/data/system/shutdown-checkpoints',
		'/data/misc/bootstat',
		'/data/misc/profiles',
		'/data/system_ce/0/shortcut_service',
	]

	mounts := os.execute('mount').output

	for target in targets {
		if !exists(target) {
			continue
		}

		is_mounted := mounts.contains(' ${target} ')

		if _likely_(enable) {
			if _likely_(is_mounted) {
				continue
			}

			stat_raw := os.execute('stat -c %u:%g:%a ${target}').output.trim_space()
			stat_parts := stat_raw.split(':')
			uid := if stat_parts.len >= 1 && stat_parts[0].len > 0 &&
				stat_parts[0].len <= 5 { stat_parts[0] } else { '1000' }
			gid := if stat_parts.len >= 2 && stat_parts[1].len > 0 &&
				stat_parts[1].len <= 5 { stat_parts[1] } else { '1000' }
			mode := if stat_parts.len >= 3 && stat_parts[2].len > 0 &&
				stat_parts[2].len <= 4 { stat_parts[2] } else { '700' }

			raw_ctx := os.execute('ls -dZ ${target}').output
			mut ctx := raw_ctx.split(' ')[0].trim_space()
			if ctx == '?' || ctx.len < 5 {
				ctx = 'u:object_r:system_data_file:s0'
			}

			sz := tmpfs_size(target)

			cmd := 'mount -t tmpfs -o size=${sz},mode=0${mode},uid=${uid},gid=${gid},context=${ctx} tmpfs ${target}'
			mut res := os.execute(cmd)

			if res.exit_code != 0 {
				cmd2 := 'mount -t tmpfs -o size=${sz},mode=0${mode},uid=${uid},gid=${gid} tmpfs ${target}'
				res = os.execute(cmd2)
			}

			if _likely_(res.exit_code == 0) {
				run('restorecon -R ${target}')
				post_mount(target, uid, gid)
				println('${term.green('✔')} Secured: ${target}')
			} else {
				println('${term.yellow('⚠')} Failed: ${target}')
			}
		} else {
			if !is_mounted {
				continue
			}
			wipe_ram(target)
			run('umount -l ${target}')
		}
	}

	clean_pstore()

	if !enable {
		run('echo 3 > /proc/sys/vm/drop_caches')
	}
}

@[inline; must_use; _cold]
fn tmpfs_size(target string) string {
	if target.contains('bugreports') || target.contains('perfetto-traces') ||
		target.contains('logd') || target.contains('/profiles') {
		return '32M'
	}
	if target.contains('recent_images') || target.contains('usagestats') ||
		target.contains('recent_tasks') {
		return '16M'
	}
	return '8M'
}

@[inline; _hot]
fn post_mount(target string, uid string, gid string) {
	if target.contains('usagestats') {
		run('mkdir -p ${target}/daily ${target}/weekly ${target}/monthly ${target}/yearly')
		run('chown -R ${uid}:${gid} ${target}')
		run('restorecon -R ${target}')
	} else if target.contains('/profiles') {
		run('mkdir -p ${target}/cur/0 ${target}/ref')
		run('chown -R ${uid}:${gid} ${target}')
		run('restorecon -R ${target}')
	}
}

@[inline; _cold]
fn clean_pstore() {
	if _likely_(exists('/sys/fs/pstore')) {
		run('rm -f /sys/fs/pstore/*')
	}
}

@[inline; _hot]
fn trigger_vibrate(duration_ms int) {
	uid := os.execute('stat -c %u /data/data/com.termux').output.trim_space()
	os.execute('su ${uid} -c "PATH=/data/data/com.termux/files/usr/bin:\$PATH LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib termux-vibrate -d ${duration_ms}"')
}

@[inline; must_use; _hot]
fn get_mag_value_from_root() f64 {
	uid := os.execute('stat -c %u /data/data/com.termux').output.trim_space()
	res := os.execute('su ${uid} -c "export PATH=/data/data/com.termux/files/usr/bin; export TMPDIR=/data/data/com.termux/files/usr/tmp; timeout 2s termux-sensor -s \'MAGNETOMETER\' -n 1"')
	if _unlikely_(res.exit_code != 0 || !res.output.contains('"values":')) {
		return -1.0
	}
	raw := res.output
	vals_str := raw.all_after('"values": [').all_before(']')
	parts := vals_str.split(',')
	if parts.len >= 3 {
		x := parts[0].trim_space().f64()
		y := parts[1].trim_space().f64()
		z := parts[2].trim_space().f64()
		return math.sqrt((x * x) + (y * y) + (z * z))
	}
	return -1.0
}

@[inline; _hot]
fn info(msg string) {
	println('${term.blue('ℹ')} ${msg}')
}

@[inline; _hot]
fn success(msg string) {
	println('${term.green('✔')} ${msg}')
}

@[inline; _hot]
fn warn(msg string) {
	println('${term.yellow('⚠')} ${msg}')
}

@[inline; _hot]
fn error2(msg string) {
	println('${term.red('✘')} ${msg}')
	time.sleep(1400 * time.millisecond)
}

@[inline; noreturn; _hot]
fn fatal(msg string) {
	println('${term.bg_red(term.white(' FATAL '))} ${msg}')
	exit(1)
}

@[packed; minify]
struct TrackedApp {
	pkg_name string
	pw       string
mut:
	timer int
	sync  int
}

@[inline; _hot]
fn exists(path string) bool {
	res := os.execute('test -e ${path}')
	return res.exit_code == 0
}

@[inline; direct_array_access; _cold]
fn kill_disk_swap() {
	swaps := os.read_file('/proc/swaps') or { return }
	lines := swaps.split_into_lines()

	for i in 1 .. lines.len {
		line := lines[i]
		if line.len < 5 {
			continue
		}
		parts := line.fields()
		if parts.len < 1 {
			continue
		}
		path := parts[0]
		if path.contains('/data/') || path.contains('/mnt/expand/') {
			info('Dangerous Disk-Swap detected: ${path}. Disabling ...')
			run('swapoff ${path}')
			size_kb := parts[2].int()
			if size_kb > 0 {
				info('Wiping swap file on disk (${size_kb} KB) for security...')
				run('dd if=/dev/urandom of=${path} bs=1K count=${size_kb} conv=fsync')
				run('rm -f ${path}')
			}
			success('Disk-swap eliminated.')
		}
	}
}

@[inline; _hot]
fn run(cmd string) {
	info('Executing: ${cmd}')
	exit_code := os.system('${cmd} 2>/dev/null')
	if _likely_(exit_code == 0) {
		success('Completed: ${cmd}')
	} else if _unlikely_(exit_code != 0) {
		warn('Failed (code ${exit_code}): ${cmd}')
	}
}

@[inline; must_use; _hot]
fn get_meta(dp string) (string, string) {
	u := os.execute('stat -c %u ${dp} 2>/dev/null').output.trim_space()
	c_raw := os.execute('ls -dZ ${dp} 2>/dev/null').output
	c := c_raw.split(' ')[0]
	if c == '' || c == '?' {
		return u, 'u:object_r:app_data_file:s0'
	}
	return u, c
}

@[inline; _hot]
fn kill_app(pkg string) {
	run('am force-stop ${pkg}')
	run('pm disable-user --user 0 ${pkg}')
	u := os.execute('stat -c %u /data/data/${pkg} 2>/dev/null').output.trim_space()
	if _likely_(u.len > 0) {
		run('pkill -9 -u ${u}')
	}
	time.sleep(1400 * time.millisecond)
}

@[inline; _hot]
fn wipe_ram(path string) {
	info('Wiping RAM (tmpfs) at ${path} ...')
	run('dd if=/dev/urandom of=${path}/wipe_file bs=1M conv=fsync || true')
	run('rm -f ${path}/wipe_file')
	run('dd if=/dev/zero of=${path}/wipe_file bs=1M conv=fsync || true')
	run('rm -f ${path}/wipe_file')
	success('RAM successfully wiped at ${path}')
}

@[noinline; direct_array_access; _cold]
fn start_app_core(pkg string, pw string) int {
	for b in pkg.bytes() {
		if _unlikely_(!((b >= 97 && b <= 122) || (b >= 65 && b <= 90) || (b >= 48 && b <= 57) || b == 46 || b == 95)) {
			return 1
		}
	}

	kill_disk_swap()

	if _unlikely_(!os.exists('/data/data/${pkg}')) {
		return 1
	}

	u, c := get_meta('/data/data/${pkg}')
	
	safe_pkg := "'${pkg}'"
	pid := pkg.replace('.', '_')
	
	dp := '/data/data/${pkg}'
	safe_dp := "'${dp}'"
	
	rp := '/mnt/ram_${pid}'
	safe_rp := "'${rp}'"
	
	vf := '/data/local/tmp/${pkg}.enc'
	safe_vf := "'${vf}'"
	
	pedp := '/data/media/0/Android/data/${pkg}'
	safe_pedp := "'${pedp}'"
	
	vedp := '/storage/emulated/0/Android/data/${pkg}'
	safe_vedp := "'${vedp}'"
	
	redp := '/mnt/runtime/write/emulated/0/Android/data/${pkg}'
	safe_redp := "'${redp}'"
	
	erp := '/mnt/ext_${pid}'
	safe_erp := "'${erp}'"
	
	evf := '/data/local/tmp/${pkg}.ext.enc'
	safe_evf := "'${evf}'"

	kill_app(pkg)
	run('umount -l ${safe_dp}')
	run('mkdir -p ${safe_rp}')

	mut needed_storage := 1024
	mut needed_data := 1024

	if _likely_(os.exists(evf) && os.exists(vf)) {
		res := os.execute('du -sm ${safe_evf} 2>/dev/null')
		res_two := os.execute('du -sm ${safe_vf} 2>/dev/null')

		if _likely_(res.exit_code == 0) {
			parts := res.output.split('\t')
			if parts.len > 0 {
				val := parts[0].int()
				if val > 0 {
					needed_storage = val * 5
				}
			}
		}

		if _likely_(res_two.exit_code == 0) {
			parts := res_two.output.split('\t')
			if parts.len > 0 {
				val := parts[0].int()
				if val > 0 {
					needed_data = val * 5
				}
			}
		}
	}

	run('mount -t tmpfs -o size=${needed_data}M,mode=771 tmpfs ${safe_rp}')

	if _likely_(os.exists(vf)) {
		cmd_main := 'openssl enc -chacha20 -d -pbkdf2 -iter 200000 -md sha512 -pass stdin -in ${safe_vf} | zstd -d | tar -xp --numeric-owner -C ${safe_rp}'
		
		mut proc_main := os.new_process('/bin/sh')
		proc_main.set_args(['-c', cmd_main])
		proc_main.set_redirect_stdio()
		proc_main.run()
		proc_main.stdin_write(pw)
		os.fd_close(proc_main.stdio_fd[0])
		proc_main.wait()
		
		if _unlikely_(proc_main.code != 0) {
			error2('WRONG PW OR BROKEN FILE')
			run('umount -f ${safe_rp}')
			run('umount -f ${safe_erp}')
			run('rm -rf ${safe_rp} ${safe_erp}')
			run('restorecon -R ${safe_dp}')
			run('pm enable ${safe_pkg}')
			run('pm hide ${pkg}')
			return 1
		}
	} else {
		run('cp -a ${safe_dp}/. ${safe_rp}/')
	}

	run('chown -R ${u}:${u} ${safe_rp}')
	run('chcon -R ${c} ${safe_rp}')
	run('mount --bind ${safe_rp} ${safe_dp}')

	if os.exists(pedp) || os.exists(evf) {
		run('umount -l ${safe_pedp}')
		run('umount -l ${safe_vedp}')
		run('umount -l ${safe_redp}')
		run('mkdir -p ${safe_erp}')
		run('mount -t tmpfs -o size=${needed_storage}M,mode=770,uid=${u},gid=9997 tmpfs ${safe_erp}')

		if os.exists(evf) {
			cmd_ext := 'openssl enc -chacha20 -d -pbkdf2 -iter 200000 -md sha512 -pass stdin -in ${safe_evf} | zstd -d | tar -xp --numeric-owner -C ${safe_erp}'
			
			mut proc_ext := os.new_process('/bin/sh')
			proc_ext.set_args(['-c', cmd_ext])
			proc_ext.set_redirect_stdio()
			proc_ext.run()
			proc_ext.stdin_write(pw)
			os.fd_close(proc_ext.stdio_fd[0])
			proc_ext.wait()

			if _unlikely_(proc_ext.code != 0) {
				error2('WRONG PW OR BROKEN FILE')
				run('umount -f ${safe_rp}')
				run('umount -f ${safe_erp}')
				run('rm -rf ${safe_rp} ${safe_erp}')
				run('restorecon -R ${safe_dp}')
				run('pm enable ${safe_pkg}')
				run('pm hide ${pkg}')
				return 1
			}
		} else {
			run('cp -a ${safe_pedp}/. ${safe_erp}/')
		}

		run('chown -R ${u}:9997 ${safe_erp}')
		run('chcon -R u:object_r:media_rw_data_file:s0 ${safe_erp}')
		run('mount --bind ${safe_erp} ${safe_pedp}')
		run('mount --bind ${safe_erp} ${safe_vedp}')
		run('nsenter -t 1 -m mount --bind ${safe_erp} ${safe_pedp}')
		run('nsenter -t 1 -m mount --bind ${safe_erp} ${safe_vedp}')
		run('nsenter -t 1 -m mount --bind ${safe_erp} ${safe_redp}')
	}

	run('pm enable ${safe_pkg}')
	run('pm unhide ${pkg}')
	return 0
}

@[inline; must_use; direct_array_access; _hot]
fn get_usage(path string) int {
	res := os.execute('df ${path}')
	if _unlikely_(res.exit_code != 0) {
		return 0
	}
	parts := res.output.fields()
	for p in parts {
		if _likely_(p.ends_with('%')) {
			return p.replace('%', '').int()
		}
	}
	return 0
}

@[noinline; direct_array_access; _cold]
fn stop_app_core(pkg string, pw string) {
	pid := pkg.replace('.', '_')
	dp := '/data/data/${pkg}'
	rp := '/mnt/ram_${pid}'
	erp := '/mnt/ext_${pid}'

	mounts := os.execute('mount').output

	if _likely_(mounts.contains(rp)) {
		if _unlikely_(get_usage(rp) >= 95) {
			println('Error: ${rp} usage is over 95%')
			return
		}
	}

	if _likely_(mounts.contains(erp)) {
		if _unlikely_(get_usage(erp) >= 95) {
			println('Error: ${erp} usage is over 95%')
			return
		}
	}

	run('am force-stop ${pkg}')
	kill_app(pkg)

	os.setenv('V_PW', pw, true)
	run('sync && echo 3 > /proc/sys/vm/drop_caches')
		if _likely_(mounts.contains(rp)) {
		run('tar -cp --numeric-owner -C ${rp} . | zstd -1 -T1 --single-thread | openssl enc -chacha20 -pbkdf2 -iter 200000 -md sha512 -salt -pass env:V_PW -out /data/local/tmp/${pkg}.enc')
	}
	run('sync && echo 3 > /proc/sys/vm/drop_caches')
	if _likely_(mounts.contains(erp)) {
		run('tar -cp --numeric-owner -C ${erp} . | zstd -1 -T1 --single-thread | openssl enc -chacha20 -pbkdf2 -iter 200000 -md sha512 -salt -pass env:V_PW -out /data/local/tmp/${pkg}.ext.enc')
	}
	
	if _likely_(exists(rp)) {
		wipe_ram(rp)
	}
	if _likely_(exists(erp)) {
		wipe_ram(erp)
	}
	os.unsetenv('V_PW')
	paths_to_unmount := [dp, '/data/media/0/Android/data/${pkg}',
		'/storage/emulated/0/Android/data/${pkg}',
		'/mnt/runtime/write/emulated/0/Android/data/${pkg}']
	for path in paths_to_unmount {
		run('umount -f ${path}')
		run('nsenter -t 1 -m umount -f ${path}')
	}
	run('umount -f ${rp}')
	run('umount -f ${erp}')
	run('rm -rf ${rp} ${erp}')
	run('restorecon -R ${dp}')
	run('pm enable ${pkg}')
	run('pm hide ${pkg}')
	run('echo 3 > /proc/sys/vm/drop_caches')
	run('sm fstrim')
}

@[noinline; _cold]
fn stop_nokill_core(pkg string, pw string) {
	pid := pkg.replace('.', '_')
	rp := '/mnt/ram_${pid}'
	erp := '/mnt/ext_${pid}'
	mounts := os.execute('mount').output
	os.setenv('V_PW', pw, true)
	if _likely_(mounts.contains(rp)) {
		run('tar -cp --numeric-owner -C ${rp} . | zstd | openssl enc -chacha20 -pbkdf2 -iter 200000 -md sha512 -salt -pass env:V_PW -out /data/local/tmp/${pkg}.enc')
	}
	if _likely_(mounts.contains(erp)) {
		run('tar -cp --numeric-owner -C ${erp} . | zstd | openssl enc -chacha20 -pbkdf2 -iter 200000 -md sha512 -salt -pass env:V_PW -out /data/local/tmp/${pkg}.ext.enc')
	}
	if _likely_(exists(rp)) {
		wipe_ram(rp)
	}
	if _likely_(exists(erp)) {
		wipe_ram(erp)
	}
	os.unsetenv('V_PW')
}

@[noinline; direct_array_access; _cold]
fn stop_nosave_core(pkg string) {
	pid := pkg.replace('.', '_')
	dp := '/data/data/${pkg}'
	rp := '/mnt/ram_${pid}'
	erp := '/mnt/ext_${pid}'
	run('am force-stop ${pkg}')
	kill_app(pkg)
	if _likely_(exists(rp)) {
		wipe_ram(rp)
	}
	if _likely_(exists(erp)) {
		wipe_ram(erp)
	}
	paths_to_unmount := [dp, '/data/media/0/Android/data/${pkg}',
		'/storage/emulated/0/Android/data/${pkg}', '/mnt/runtime/write/emulated/0/Android/data/${pkg}']
	for path in paths_to_unmount {
		run('umount -f ${path}')
		run('nsenter -t 1 -m umount -f ${path}')
	}
	run('umount -f ${rp}')
	run('umount -f ${erp}')
	run('rm -rf ${rp} ${erp}')
	run('restorecon -R ${dp}')
	run('pm enable ${pkg}')
	run('pm hide ${pkg}')
	run('echo 3 > /proc/sys/vm/drop_caches')
	run('sm fstrim')
}

fn C.execl(path &u8, arg0 &u8, ...) int

@[noinline; noreturn; direct_array_access; _hot]
fn purge_all() {
    manage_snapshot_protection(false)
    mounts_data := os.read_file('/proc/mounts') or { '' }

    for line in mounts_data.split_into_lines() {
        fields := line.split(' ')
        if fields.len < 2 { continue }
        target := fields[1]

        if target.contains('/mnt/ram_') || target.contains('/mnt/ext_') {
            prefix := if target.contains('/mnt/ram_') { '/mnt/ram_' } else { '/mnt/ext_' }
            pkg_raw := target.all_after(prefix).replace('_', '.')

            if _unlikely_(!is_valid_pkg(pkg_raw)) {
                error2('Skipping invalid mount target: ${target}')
                continue
            }

            pkg := pkg_raw
            os.execute('am force-stop ${pkg}')
            run('pm enable ${pkg}')
            run('pm unhide ${pkg}') // dummy data before triggering panic in unmounted data is so important (they can found application and hiding apps can be a red flag for you so it's better to do not)
            stat_res := os.execute('stat -c %u /data/data/${pkg}')
            if stat_res.exit_code == 0 {
                uid := stat_res.output.trim_space()
                os.execute('pkill -9 -u ${uid}')
            } else {
                os.execute('killall -9 ${pkg}')
            }

            wipe_ram(target)
            os.execute('umount -l "${target}"')
        }
    }

    enc_files := os.glob('/data/local/tmp/*.enc') or { []string{} }
    for f in enc_files {
        if _likely_(os.exists(f) && !os.is_link(f)) {
            os.execute('shred -n 1 -z -u "${f}"')
        }
    }

    self := os.executable()
    info('Emergency Purge Complete. Rebooting...')

    cmd := 'shred -n 1 -z -u "' + self + '" ; echo 3 > /proc/sys/vm/drop_caches ; sync ; sm fstrim ; logcat -b all -c ; reboot'
    C.execl(
        c'/system/bin/sh',
        c'sh',
        c'-c',
        cmd.str,
        unsafe { nil }
    )

    os.execute('reboot')
    exit(1)
}

@[inline; must_use; _hot]
fn get_fg_app() string {
	return get_fg_app_safe() or { '' }
}

@[inline; must_use; _hot]
fn get_fg_app_safe() ?string {
	res := os.execute('dumpsys activity activities | grep "ResumedActivity"')
	if _unlikely_(res.exit_code != 0) {
		return none
	}
	for line in res.output.split_into_lines() {
		if line.contains('/') {
			raw := line.all_before('/')
			parts := raw.trim_space().split(' ')
			if parts.len == 0 {
				continue
			}
			mut p := parts.last()
			if p.contains('{') {
				p = p.all_after_last('{')
			}
			if p.contains(':') {
				p = p.all_after_last(':')
			}
			p = p.replace('u0', '').trim_space()
			if p == '' {
				continue
			}
			return p
		}
	}
	return none
}

@[inline; must_use; _hot]
fn get_first_int(output string) int {
	parts := output.split('\t')
	if parts.len > 0 && parts[0] != '' {
		return parts[0].int()
	}
	return 0
}

__global last_gui_call = i64(0)

@[inline; must_use; _hot]
fn get_gui_pw(pkg string) string {
	back_to_termuxapi()
	now := time.now().unix()
	if _likely_(last_gui_call == 0 || (now - last_gui_call) > 10) {
		time.sleep(1 * time.second)
	}
	last_gui_call = now

	uid := os.execute('stat -c %u /data/data/com.termux').output.trim_space()
	res := os.execute('su ${uid} -c "export PATH=/data/data/com.termux/files/usr/bin; export TMPDIR=/data/data/com.termux/files/usr/tmp; termux-dialog text -p -t \'${pkg} - MimicFS\' -i \'Enter Key\'"')

	if _unlikely_(res.exit_code != 0 || !res.output.contains('"text":')) {
		return ''
	}

	if _unlikely_(res.output.contains('"code": -2')) {
		return ''
	}

	pw := res.output.all_after('"text": "').all_before('"')
	return pw.trim_space()
}

@[noinline; _cold]
fn run_daemon(panic_pw string, time_count_str string, sync_count_str string, mg_str string) {
	guard := PwGuard.new()
	kill_disk_swap()
	t_limit := time_count_str.int()
	sync := sync_count_str.int()
	mg := mg_str.int()
	if _unlikely_(t_limit <= 0 || sync < 0 || t_limit <= sync || mg < 0) {
		fatal('BAD_TIMER_CONF')
	}

	info('[MimicFS] Daemon Running ...')
	os.execute('su -c "dumpsys deviceidle whitelist +com.termux.api"')

	mut baseline := 0.0
	mut threshold := 0.0
	if mg != 0 {
		trigger_vibrate(400)
		baseline = get_mag_value_from_root()
		threshold = 15.0
	}
	mut tracked_apps := []TrackedApp{}
	mut last_app := ''

	files := os.ls('/data/local/tmp') or { [] }
	for file in files {
		if file.ends_with('.enc') && !file.ends_with('.ext.enc') {
			pkg := file.before('.enc')
			pid := pkg.replace('.', '_')

			if os.exists('/mnt/ram_${pid}') {
				info('    [ACTION] Key needed for ${pkg}')
				pw := get_gui_pw(pkg)
				if pw == '' {
					continue
				}
				if !tracked_apps.any(it.pkg_name == pkg) {
					pw1 := guard.encode(pw) or { panic(err) }
					tracked_apps << TrackedApp{
						pkg_name: pkg
						pw:       pw1
						timer:    t_limit
						sync:     sync
					}
					success('${pkg} is now running in RAM')
				}
			}
		}
	}

	for {
		if mg != 0 {
			current_mag := get_mag_value_from_root()

			if current_mag > 0 {
				diff := math.abs(current_mag - baseline)
				if diff > threshold {
					warn('!!! HARDWARE ANOMALY DETECTED (Diff: ${diff}) !!!')
					trigger_vibrate(1000)
					for i in 0 .. tracked_apps.len {
						tracked_apps[i].timer = 0
					}
					baseline = current_mag
				}
			}
		}
		curr := get_fg_app()
		if curr != '' && curr != last_app {
			last_app = curr

			enc_path := '/data/local/tmp/${curr}.enc'
			if exists(enc_path) {
				pid := curr.replace('.', '_')
				mount_path := '/mnt/ram_${pid}'

				if !exists(mount_path) {
					info('    [ACTION] Key needed for ${curr}')
					run('am force-stop ${curr}')
					back_to_termuxapi()
					pw := get_gui_pw(curr)
					if pw == '' {
						continue
					}

					if pw == panic_pw {
						purge_all()
						break
					}

					if pw != '' {
						if start_app_core(curr, pw) == 0 && !tracked_apps.any(it.pkg_name == curr) {
							pw1 := guard.encode(pw) or { panic(err) }
							tracked_apps << TrackedApp{
								pkg_name: curr
								pw:       pw1
								timer:    t_limit
								sync:     sync
							}
							success('${curr} is now running in RAM')
						}

						run("su -c 'pkg_name=\"${curr}\"; act_name=\$(cmd package resolve-activity --brief \$pkg_name | tail -n 1); am start -n \$act_name'")
					}
				}
			}
		}

		for i := 0; i < tracked_apps.len; i++ {
			mut t_app := tracked_apps[i]
			if curr == t_app.pkg_name {
				tracked_apps[i].timer = t_limit
				if sync != 0 {
					tracked_apps[i].sync--

					if tracked_apps[i].sync <= 0 {
						info('    [SYNC] Sync ${t_app.pkg_name} to ROM')
						pwd := guard.decode(t_app.pw) or { panic(err) }
						stop_nokill_core(t_app.pkg_name, pwd)
						tracked_apps[i].sync = sync
					}
				}
			} else {
				tracked_apps[i].timer--
				if tracked_apps[i].timer <= 0 {
					info('    [TIMEOUT] Closing ${t_app.pkg_name}')
					pwd := guard.decode(t_app.pw) or { panic(err) }
					stop_app_core(t_app.pkg_name, pwd)
					tracked_apps.delete(i)
					i--
					stop_nosave_core(t_app.pkg_name)
				}
			}
		}

		time.sleep(1000 * time.millisecond)
	}
	unsafe {guard.free()}
}

@[inline; _cold]
fn add_pkg_core(pkg string, pw string) {
	pid := pkg.replace('.', '_')
	f := '/data/local/tmp/${pid}.enc'

	if _unlikely_(os.exists(f)) {
		fatal('DOUBLE_ADD: Package file already exists at ${f}')
	}

	start_app_core(pkg, pw)
	time.sleep(1000 * time.millisecond)
	stop_app_core(pkg, pw)
}

@[inline; _cold]
fn cpw_core(pkg string, pw string, new_pw string) {
	start_app_core(pkg, pw)
	time.sleep(1000 * time.millisecond)
	stop_app_core(pkg, new_pw)
}

@[noinline; _cold]
fn rem_pkg_core(pkg string) {
    if _unlikely_(!is_valid_pkg(pkg)) {
        error2('Invalid package name')
    }
    f := '/data/local/tmp/${pkg}.enc'
    ef := '/data/local/tmp/${pkg}.ext.enc'
    mut files_to_wipe := []string{}
    if _likely_(os.exists(f)) { files_to_wipe << f }
    if os.exists(ef) { files_to_wipe << ef }

    if _unlikely_(files_to_wipe.len == 0) {
         error2('DOUBLE_REM: No files found.')
         return
    }
    for path in files_to_wipe {
        if _unlikely_(os.is_link(path)) {
            warn('Security Warning: ${path} is a symlink! Skipping.')
            continue
        }
        info('Wiping: ${path}')
        res := os.execute('shred -n 1 -z -u "${path}"')
        if _unlikely_(res.exit_code != 0) {
            error2('Failed to shred ${path}: ${res.output}')
            return
        }
    }
    os.execute('sm fstrim')
    success('Package ${pkg} removed securely.')
}

@[inline; _hot]
fn list_core() {
	files := os.ls('/data/local/tmp') or { [] }
	println(term.bold('${'PACKAGE NAME':-35} | ${'STATUS':-10} | ${'STORAGE'}'))
	println('-'.repeat(60))

	for file in files {
		if file.ends_with('.enc') && !file.ends_with('.ext.enc') {
			pkg := file.before('.enc')
			pid := pkg.replace('.', '_')

			status := if exists('/mnt/ram_${pid}') {
				term.green('ALIVE')
			} else {
				term.gray('SLEEPING')
			}

			size := os.execute('du -h /data/local/tmp/${file}').output.split('\t')[0]
			println('${pkg:-35} | ${status:-10} | ${size}')
		}
	}
}

@[inline; must_use; _hot]
fn is_valid_pkg(s string) bool {
	if _unlikely_(s.len == 0 || s.len > 223) {
		return false
	}

	if _unlikely_(s.contains('..') || s.contains('/')) {
		error2('BAD_PKG_NAME')
		return false
	}

	if _unlikely_(s[0] == `.` || s[s.len - 1] == `.`) {
		error2('BAD_PKG_NAME')
		return false
	}

	mut has_dot := false

	for c in s {
		if c == `.` {
			has_dot = true
		} else if (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`) || (c >= `0` && c <= `9`) || c == `_` {
			continue
		} else {
			error2('BAD_PKG_NAME')
			return false
		}
	}

	if !has_dot {
		return false
	}

	if _unlikely_(!os.exists('/data/data/${s}')) {
		return false
	}

	return true
}

__global last_dialog_call = i64(0)

@[inline; must_use; _hot]
fn get_input_dialog(title string, hint string, is_pw bool) string {
	back_to_termuxapi()
	now := time.now().unix()
	if _unlikely_(last_dialog_call == 0 || (now - last_dialog_call) > 10) {
		time.sleep(1 * time.second)
	}
	last_dialog_call = now

	uid := os.execute('stat -c %u /data/data/com.termux').output.trim_space()
	p_flag := if is_pw { '-p' } else { '' }
	res := os.execute('su ${uid} -c "export PATH=/data/data/com.termux/files/usr/bin; export TMPDIR=/data/data/com.termux/files/usr/tmp; termux-dialog text ${p_flag} -t \'${title}\' -i \'${hint}\'"')
	if _unlikely_(!res.output.contains('"text":') || res.output.contains('"code": -2')) {
		return ''
	}
	return res.output.all_after('"text": "').all_before('"').trim_space()
}

@[noinline; _cold]
fn extc_start(pkg string, path string, needed_data int) int {
	for b in pkg.bytes() {
		if _unlikely_(!((b >= 97 && b <= 122) || (b >= 65 && b <= 90) || (b >= 48 && b <= 57) || b == 46 || b == 95)) {
			return 1
		}
	}
	for b in path.bytes() {
		if _unlikely_(!((b >= 97 && b <= 122) || (b >= 65 && b <= 90) || (b >= 48 && b <= 57))) {
			return 1
		}
	}

	s_path_1 := "/data/media/0/${path}"
	s_path_2 := "/storage/emulated/0/${path}"
	s_path_3 := "/mnt/extc_${path}"
	s_redp := "/mnt/runtime/write/emulated/0/${path}"

	if _unlikely_(!os.exists(s_path_1)) {
		return 1
	}

	stat_res := os.execute('stat -c %u /data/data/${pkg}')
	if _unlikely_(stat_res.exit_code != 0) {
		return 1
	}
	u := stat_res.output.trim_space()

	run("umount -l ${s_path_1}")
	run("umount -l ${s_path_2}")
	run("umount -l ${s_redp}")
	run("umount -l ${s_path_3}")

	run("mkdir -p ${s_path_3}")

	if _likely_(os.execute('mount -t tmpfs -o size=${needed_data}M,mode=771 tmpfs ${s_path_3}').exit_code == 0) {
		run("chown -R ${u}:${u} ${s_path_3}")
		run("chcon -R u:object_r:media_rw_data_file:s0 ${s_path_3}")
		run("chmod 777 ${s_path_3}")
		run("mount --bind ${s_path_3} ${s_path_2}")
		run("mount --bind ${s_path_3} ${s_path_1}")
		run('nsenter -t 1 -m mount --bind ${s_path_3} ${s_redp}')
		run('nsenter -t 1 -m mount --bind ${s_path_3} ${s_path_2}')
		run('nsenter -t 1 -m mount --bind ${s_path_3} ${s_path_1}')
		return 0
	}

	return 1
}

@[noinline; _cold]
fn extc_stop(path string) int {
	for b in path.bytes() {
		if _unlikely_(!((b >= 97 && b <= 122) || (b >= 65 && b <= 90) || (b >= 48 && b <= 57))) {
			return 1
		}
	}

	s_path_1 := "/data/media/0/${path}"
	s_path_2 := "/storage/emulated/0/${path}"
	s_path_3 := "/mnt/extc_${path}"
	s_redp := "/mnt/runtime/write/emulated/0/${path}"

	run("nsenter -t 1 -m umount -l ${s_path_1}")
	run("nsenter -t 1 -m umount -l ${s_path_2}")
	run("nsenter -t 1 -m umount -l ${s_redp}")
	run("umount -l ${s_path_1}")
	run("umount -l ${s_path_2}")
	run("umount -l ${s_path_3}")
	run("rm -rf ${s_path_3}")

	return 0
}

@[inline; _hot]
fn back_to_termux() {
	os.execute('su -c am start -n com.termux/.app.TermuxActivity')
}

@[inline; _hot]
fn back_to_termuxapi() {
	os.execute('su -c am start -n com.termux.api/.activities.TermuxAPIMainActivity')
	time.sleep(300 * time.millisecond)
}

@[inline; _cold]
fn resize_app_tmpfs(pkg string, delta_mb int, ext bool) int {
	for b in pkg.bytes() {
		if _unlikely_(!((b >= 97 && b <= 122) || (b >= 65 && b <= 90) || (b >= 48 && b <= 57) || b == 46 || b == 95)) {
			return 1
		}
	}

	if _unlikely_(delta_mb == 0) { // lmao
		return 0
	}

	pid := pkg.replace('.', '_')

	mp := if ext {
		'/mnt/ext_${pid}'
	} else {
		'/mnt/ram_${pid}'
	}
	safe_mp := "'${mp}'"

	if !os.is_dir(mp) {
		error2('Mount point not found: ${mp}')
		return 1
	}

	mounts := os.read_file('/proc/mounts') or {
		error2('Cannot read /proc/mounts')
		return 1
	}

	mut current_kb := 0
	for line in mounts.split('\n') {
		fields := line.split(' ')
		if fields.len >= 4 && fields[1] == mp {
			for opt in fields[3].split(',') {
				if opt.starts_with('size=') {
					val := opt[5..]
					if val.ends_with('k') {
						current_kb = val[..val.len - 1].int()
					} else if val.ends_with('m') {
						current_kb = val[..val.len - 1].int() * 1024
					} else if val.ends_with('g') {
						current_kb = val[..val.len - 1].int() * 1048576
					} else {
						current_kb = val.int() / 1024
					}
					break
				}
			}
			break
		}
	}

	if current_kb <= 0 {
		error2('Cannot find tmpfs size for ${mp}')
		return 1
	}

	current_mb := current_kb / 1024
	new_mb := current_mb + delta_mb

	if _unlikely_(new_mb < 1) {
		error2('New size too small: ${new_mb}MB')
		return 1
	}

	run('mount -o remount,size=${new_mb}M ${safe_mp}')
	println('\x1b[32m[OK]\x1b[0m Resized ${mp}: ${current_mb}MB -> ${new_mb}MB')
	return 0
}

@[inline; _cold]
fn lock_all_core(pw string) {
	mounts := os.read_file('/proc/mounts') or { return }
	for line in mounts.split('\n') {
		fields := line.split(' ')
		if fields.len >= 2 && fields[1].starts_with('/mnt/ram_') {
			pid := fields[1].replace('/mnt/ram_', '')
			pkg := pid.replace('_', '.')
			stop_app_core(pkg, pw)
		}
	}
}

@[packed; minify]
struct App {
mut:
	tui          &tui.Context = unsafe { nil }
	selected_idx int
	options      []string
	keys         []string
	frame_count  int
}

@[inline; must_use; _hot]
fn rainbow(counter int, offset int) (u8, u8, u8) {
	pos := ((counter * 3) + offset * 40) % 360
	sector := pos / 60
	f := u8((pos % 60) * 255 / 60)
	if sector == 0 {
		return 255, f, 0
	}
	if sector == 1 {
		return u8(255 - f), 255, 0
	}
	if sector == 2 {
		return 0, 255, f
	}
	if sector == 3 {
		return 0, u8(255 - f), 255
	}
	if sector == 4 {
		return f, 0, 255
	}
	return 255, 0, u8(255 - f)
}

@[inline; must_use; _hot]
fn breath(counter int, speed int, lo int, hi int) u8 {
	cyc := if speed > 1 { speed } else { 2 }
	pos := counter % cyc
	half := cyc / 2
	if pos < half {
		return u8(lo + pos * (hi - lo) / half)
	}
	return u8(hi - (pos - half) * (hi - lo) / half)
}

@[inline; must_use; _hot]
fn sparkle(counter int) string {
	chars := ['✦', '✧', '⋆', '★', '✦', '⊹']
	return chars[(counter / 8) % chars.len]
}

@[inline; must_use; _hot]
fn get_item_color(idx int) (u8, u8, u8) {
	if idx <= 2 {
		return 100, 210, 255
	}
	if idx == 3 || idx == 6 {
		return 255, 190, 70
	}
	if idx == 4 {
		return 120, 230, 160
	}
	if idx == 5 {
		return 255, 90, 90
	}
	if idx >= 7 && idx <= 9 {
		return 150, 175, 255
	}
	if idx == 10 {
		return 190, 85, 85
	}
	return 195, 160, 255
}

@[inline; must_use; _hot]
fn get_section(idx int) string {
	return match idx {
		0 { 'APP MANAGEMENT' }
		3 { 'SYSTEM & CONFIG' }
		7 { 'ADVANCED' }
		11 { 'TOOLS' }
		else { '' }
	}
}

@[inline; must_use; _hot]
fn get_section_color(idx int) (u8, u8, u8) {
	if idx == 0 {
		return 70, 200, 255
	}
	if idx == 3 {
		return 255, 200, 70
	}
	if idx == 7 {
		return 130, 160, 255
	}
	if idx == 11 {
		return 200, 140, 255
	}
	return 100, 100, 120
}

fn frame(x voidptr) {
	mut app := unsafe { &App(x) }
	mut t := app.tui
	t.clear()
	w := t.window_width
	h := t.window_height
	app.frame_count++
	fc := app.frame_count

	bw := if w > 6 { w - 6 } else { 2 }
	br := breath(fc, 80, 20, 55)
	br_g := u8(int(br) + 8)
	br_b := u8(int(br) + 35)

	t.set_cursor_position(3, 1)
	t.set_color(r: br, g: br_g, b: br_b)
	t.write('╭' + '─'.repeat(bw) + '╮')

	t.set_cursor_position(3, 2)
	t.set_color(r: br, g: br_g, b: br_b)
	t.write('│')
	t.set_cursor_position(3 + bw + 1, 2)
	t.write('│')

	title := 'M I M I C F S'
	tx := if w > title.len + 10 { (w - title.len) / 2 - 1 } else { 5 }
	t.set_cursor_position(tx, 2)
	sp := sparkle(fc)
	lr, lg, lb := rainbow(fc, 0)
	t.set_color(r: lr, g: lg, b: lb)
	t.bold()
	t.write(sp + ' ')
	for ci in 0 .. title.len {
		cr, cg, cb := rainbow(fc, ci)
		t.set_color(r: cr, g: cg, b: cb)
		t.bold()
		end := ci + 1
		t.write(title[ci..end])
	}
	rr, rg, rb := rainbow(fc, title.len)
	t.set_color(r: rr, g: rg, b: rb)
	t.write(' ' + sp)
	t.reset()

	t.set_cursor_position(3, 3)
	t.set_color(r: br, g: br_g, b: br_b)
	t.write('│')
	t.set_cursor_position(3 + bw + 1, 3)
	t.write('│')

	sub := '◇ Secure Data Manager ◇'
	sub_x := if w > sub.len + 6 { (w - sub.len) / 2 } else { 5 }
	t.set_cursor_position(sub_x, 3)
	sv := breath(fc, 50, 45, 95)
	t.set_color(r: sv, g: u8(int(sv) + 5), b: u8(int(sv) + 25))
	t.write(sub)
	t.reset()

	t.set_cursor_position(3, 4)
	t.set_color(r: br, g: br_g, b: br_b)
	t.write('╰' + '─'.repeat(bw) + '╯')
	t.reset()

	mut y := 6
	for i in 0 .. app.options.len {
		if y >= h - 3 {
			break
		}

		sec := get_section(i)
		if sec.len > 0 {
			if i > 0 {
				y++
			}
			if y >= h - 3 {
				break
			}

			scr, scg, scb := get_section_color(i)
			sk := sparkle(fc + i * 7)
			t.set_cursor_position(5, y)
			t.set_color(r: u8(int(scr) / 3), g: u8(int(scg) / 3), b: u8(int(scb) / 3))
			t.write('───')
			t.set_color(r: scr, g: scg, b: scb)
			t.bold()
			t.write(' ' + sk + ' ' + sec + ' ' + sk + ' ')
			t.reset()
			t.set_color(r: u8(int(scr) / 3), g: u8(int(scg) / 3), b: u8(int(scb) / 3))
			t.write('───')
			t.reset()
			y++
			if y >= h - 3 {
				break
			}
		}

		if i == app.selected_idx {
			sel_bg := breath(fc, 40, 12, 30)
			sel_bg_g := u8(int(sel_bg) + 8)
			sel_bg_b := u8(int(sel_bg) + 28)

			t.set_cursor_position(1, y)
			t.set_bg_color(r: sel_bg, g: sel_bg_g, b: sel_bg_b)
			t.write(' '.repeat(w))

			t.set_cursor_position(4, y)
			t.set_bg_color(r: sel_bg, g: sel_bg_g, b: sel_bg_b)

			bar_r, bar_g, bar_b := rainbow(fc, 0)
			t.set_color(r: bar_r, g: bar_g, b: bar_b)
			t.bold()
			t.write('▎ ')

			t.set_color(r: 0, g: 255, b: 190)
			t.write('▸ ')

			kr, kg, kb := rainbow(fc, 5)
			t.set_color(r: kr, g: kg, b: kb)
			t.write(app.keys[i])

			t.set_color(r: 60, g: 70, b: 100)
			t.write(' │ ')

			if i == 5 {
				pulse_r := breath(fc, 20, 180, 255)
				t.set_color(r: pulse_r, g: u8(int(pulse_r) / 4), b: u8(int(pulse_r) / 4))
			} else {
				t.set_color(r: 255, g: 255, b: 255)
			}
			t.write(app.options[i])

			sel_sp := sparkle(fc + 2)
			t.set_color(r: bar_r, g: bar_g, b: bar_b)
			t.write('  ' + sel_sp)
			t.reset()
		} else {
			cr, cg, cb := get_item_color(i)
			t.set_cursor_position(7, y)

			t.set_color(r: 50, g: 55, b: 75)
			t.write(app.keys[i])

			t.set_color(r: 30, g: 33, b: 48)
			t.write(' │ ')

			t.set_color(r: cr, g: cg, b: cb)
			t.write(app.options[i])
			t.reset()
		}
		y++
	}

	t.set_cursor_position(3, h - 2)
	t.set_color(r: br, g: br_g, b: br_b)
	t.write('─'.repeat(bw))
	t.reset()

	t.set_cursor_position(1, h - 1)
	t.set_bg_color(r: 10, g: 12, b: 20)
	t.write(' '.repeat(w))
	t.set_cursor_position(3, h - 1)
	t.set_bg_color(r: 10, g: 12, b: 20)
	t.set_color(r: 80, g: 160, b: 255)
	t.bold()
	t.write('↑↓')
	t.reset()
	t.set_bg_color(r: 10, g: 12, b: 20)
	t.set_color(r: 50, g: 55, b: 72)
	t.write(' Navigate  ')
	t.set_color(r: 80, g: 230, b: 160)
	t.bold()
	t.write('⏎')
	t.reset()
	t.set_bg_color(r: 10, g: 12, b: 20)
	t.set_color(r: 50, g: 55, b: 72)
	t.write(' Select  ')
	t.set_color(r: 220, g: 80, b: 80)
	t.bold()
	t.write('Q')
	t.reset()
	t.set_bg_color(r: 10, g: 12, b: 20)
	t.set_color(r: 50, g: 55, b: 72)
	t.write(' Quit')
	t.reset()

	t.set_cursor_position(1, h)
	t.set_bg_color(r: 6, g: 8, b: 14)
	t.write(' '.repeat(w))
	t.set_cursor_position(3, h)
	t.set_bg_color(r: 6, g: 8, b: 14)
	vsp := sparkle(fc + 5)
	vr, vg, vb := rainbow(fc, 10)
	t.set_color(r: u8(int(vr) / 6), g: u8(int(vg) / 6), b: u8(int(vb) / 6))
	t.write(vsp + ' MimicFS 1.3-PE ' + vsp)
	t.reset()

	t.flush()
}

fn event(e &tui.Event, x voidptr) {
	mut app := unsafe { &App(x) }
	if e.typ == .key_down {
		match e.code {
			.up {
				if app.selected_idx > 0 {
					app.selected_idx--
				}
			}
			.down {
				if app.selected_idx < app.options.len - 1 {
					app.selected_idx++
				}
			}
			._1 {
				app.selected_idx = 0
			}
			._2 {
				app.selected_idx = 1
			}
			._3 {
				app.selected_idx = 2
			}
			._4 {
				app.selected_idx = 3
			}
			._5 {
				app.selected_idx = 4
			}
			._6 {
				app.selected_idx = 5
			}
			._7 {
				app.selected_idx = 6
			}
			._8 {
				app.selected_idx = 7
			}
			._9 {
				app.selected_idx = 8
			}
			._0 {
				app.selected_idx = 9
			}
			.d {
				app.selected_idx = 11
			}
			.c {
				app.selected_idx = 12
			}
			.e {
				app.selected_idx = 13
			}
			.r {
				app.selected_idx = 14
			}
			.s {
				app.selected_idx = 15
			}
			.l {
				app.selected_idx = 16
			}
			.u {
				app.selected_idx = 17
			}
			.enter {
				println('')
				os.execute('clear')
				match app.selected_idx {
					0 {
						pkg := get_input_dialog('Add App', 'Package Name (e.g. org.telegram.messenger)',
							false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						pw := get_input_dialog('Set Key', 'Encryption Password', true)
						pw2 := get_input_dialog('Set Key Again', 'Encryption Password',
							true)
						if pw == '' || pw != pw2 {
							back_to_termux()
							return
						}
						back_to_termux()
						add_pkg_core(pkg, pw)
					}
					1 {
						pkg := get_input_dialog('Start App', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						pw := get_input_dialog('Enter Key', 'Password', true)
						if pw == '' {
							back_to_termux()
							return
						}
						back_to_termux()
						start_app_core(pkg, pw)
					}
					2 {
						pkg := get_input_dialog('Stop App', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						pw := get_input_dialog('Verify Key', 'Password', true)
						pw2 := get_input_dialog('Verify Key Again', 'Password', true)
						if pw == '' || pw2 != pw {
							back_to_termux()
							return
						}
						back_to_termux()
						stop_app_core(pkg, pw)
					}
					3 {
						p_pw := get_input_dialog('Daemon Setup', 'Panic Password (Wipe key)',
							true)
						if p_pw == '' {
							back_to_termux()
							return
						}
						tmo := get_input_dialog('Config', 'Auto-Lock Timeout (seconds)',
							false)
						if tmo == '' {
							back_to_termux()
							return
						}
						syn := get_input_dialog('Config', 'Sync Interval (seconds) - 0 to disable',
							false)
						if syn == '' {
							back_to_termux()
							return
						}
						mg := get_input_dialog('Config', 'Magnetic sensor (uT) - 0 to disable',
							false)
						if mg == '' {
							back_to_termux()
							return
						}
						back_to_termux()
						run_daemon(p_pw, tmo, syn, mg)
					}
					4 {
						list_core()
						time.sleep(3000 * time.millisecond)
					}
					5 {
						purge_all()
					}
					6 {
						pkg := get_input_dialog("Change App's password", 'Package Name',
							false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						pw := get_input_dialog('Verify Key', 'Password', true)
						pw2 := get_input_dialog('Verify Key Again', 'Password', true)
						if pw == '' || pw2 != pw {
							back_to_termux()
							return
						}
						new_pw := get_input_dialog('New Verify Key', 'Password', true)
						if new_pw == '' {
							back_to_termux()
							return
						}
						back_to_termux()
						cpw_core(pkg, pw, new_pw)
					}
					7 {
						pkg := get_input_dialog('Remove App', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						back_to_termux()
						rem_pkg_core(pkg)
					}
					8 {
						pkg := get_input_dialog('Force Stop App', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						back_to_termux()
						stop_nosave_core(pkg)
					}
					9 {
						pkg := get_input_dialog('Sync App', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						pw := get_input_dialog('Set Key', 'Encryption Password', true)
						pw2 := get_input_dialog('Set Key Again', 'Encryption Password',
							true)
						if pw == '' || pw2 != pw {
							back_to_termux()
							return
						}
						back_to_termux()
						stop_nokill_core(pkg, pw)
					}
					10 {
						exit(0)
					}
					11 {
						despy()
					}
					12 {
						space := get_input_dialog('Config', 'The size of space in GB',
							false).int()
						back_to_termux()
						if space > 0 {
							deep_cleaner_core(space)
						}
					}
					13 {
						pkg := get_input_dialog('Extc', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						path := get_input_dialog('Extc', 'Path Name (example /sdcard/yourpath = yourpath)',
							false)
						if path == '' {
							back_to_termux()
							return
						}
						size := get_input_dialog('Config', 'the size of tmpfs (in MB)',
							false)
						if size != '' {
							extc_start(pkg, path, size.int())
						}
						back_to_termux()
					}
					14 {
						path := get_input_dialog('UnExtc', 'Path Name (example /sdcard/yourpath = yourpath)',
							false)
						back_to_termux()
						if path != '' {
							extc_stop(path)
						}
					}
					15 {
						pkg := get_input_dialog('Resize Tmpfs', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						delta := get_input_dialog('Resize Tmpfs', 'Size change in MB (e.g. 256 or -128)', false)
						if delta == '' {
							back_to_termux()
							return
						}
						ext_str := get_input_dialog('Resize Tmpfs', 'External storage? (y/n)', false)
						back_to_termux()
						ext := ext_str == 'y' || ext_str == 'Y'
						resize_app_tmpfs(pkg, delta.int(), ext)
					}
					16 {
						pw := get_input_dialog('Verify Key', 'Encryption Password', true)
						pw2 := get_input_dialog('Verify Key Again', 'Encryption Password', true)
						if pw == '' || pw2 != pw {
							back_to_termux()
							return
						}
						back_to_termux()
						lock_all_core(pw)
					}
					17 {
						pkg := get_input_dialog('Unhide An App', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						back_to_termux()
						unhide(pkg)
					}
					else {}
				}
			}
			.q {
				exit(0)
			}
			else {}
		}
	}
}

@[inline; _hot]
fn check_dp() {
	if _unlikely_(os.execute('openssl 2>/dev/null').exit_code != 0) {
		fatal('There is no openssl installed')
	}
	if _unlikely_(os.execute('zstd -h 2>/dev/null').exit_code != 0) {
		fatal('There is no zstd installed')
	}
	if _unlikely_(os.execute('tar --help 2>/dev/null').exit_code != 0) {
		fatal('There is no tar installed')
	}
	if _unlikely_(os.execute('shred --help 2>/dev/null').exit_code != 0) {
		fatal('There is no shred installed')
	}
	if _unlikely_(os.execute('which termux-dialog 2>/dev/null').exit_code != 0) {
		fatal('There is no termux api installed OR you are in usermode')
	}
	if _unlikely_(os.execute('ls /data/data/com.termux.api 2>/dev/null').exit_code != 0) {
		fatal('There is no termux api (apk file) installed')
	}
}

@[inline; must_use]
fn read_pw(prompt string) string {
	eprint(prompt)
	os.system('stty -echo 2>/dev/null')
	line := os.get_raw_line().trim_space()
	os.system('stty echo 2>/dev/null')
	eprintln('')
	return line
}

@[inline; must_use]
fn read_input(prompt string) string {
	eprint(prompt)
	return os.get_raw_line().trim_space()
}

@[inline; noreturn; _hot]
fn cli_help() {
	println('Usage: mimicfs <command> [args]')
	println('')
	println('Commands:')
	println('  add <pkg>            Add new app')
	println('  start <pkg>          Start / Mount app')
	println('  stop <pkg>           Stop / Sync app')
	println('  forcestop <pkg>      Force stop without saving')
	println('  sync <pkg>           Sync app without killing')
	println('  remove <pkg>         Remove app')
	println('  cpw <pkg>            Change app password')
	println('  list                 List managed apps')
	println('  purge                Emergency purge all')
	println('  lockall              Lock all active apps')
	println('  resize <pkg>         Resize app tmpfs')
	println('  daemon               Run watchdog daemon')
	println('  despy                Despy')
	println('  deepclean            Deep cleaning')
	println('  extc <pkg> <path>    Mount custom path')
	println('  unextc <path>        Unmount custom path')
	println('  unhide <pkg>         Unhide an app')
	println('')
	println('Run without arguments for TUI mode')
	exit(0)
}

@[inline; _hot]
fn cli_mode(args []string) {
	check_dp()

	if args.len == 0 || args[0] == 'help' || args[0] == '-h' || args[0] == '--help' {
		cli_help()
		return
	}

	match args[0] {
		'add' {
			if args.len < 2 {
				fatal('Usage: mimicfs add <package>')
			}
			pkg := args[1]
			if !is_valid_pkg(pkg) {
				fatal('Invalid package name')
			}
			pw := read_pw('Password: ')
			if pw == '' {
				fatal('Empty password')
			}
			pw2 := read_pw('Password again: ')
			if pw != pw2 {
				fatal('Passwords do not match')
			}
			add_pkg_core(pkg, pw)
		}
		'start' {
			if args.len < 2 {
				fatal('Usage: mimicfs start <package>')
			}
			pkg := args[1]
			if !is_valid_pkg(pkg) {
				fatal('Invalid package name')
			}
			pw := read_pw('Password: ')
			if pw == '' {
				fatal('Empty password')
			}
			exit(start_app_core(pkg, pw))
		}
		'stop' {
			if args.len < 2 {
				fatal('Usage: mimicfs stop <package>')
			}
			pkg := args[1]
			if !is_valid_pkg(pkg) {
				fatal('Invalid package name')
			}
			pw := read_pw('Password: ')
			if pw == '' {
				fatal('Empty password')
			}
			pw2 := read_pw('Password again: ')
			if pw != pw2 {
				fatal('Passwords do not match')
			}
			stop_app_core(pkg, pw)
		}
		'forcestop' {
			if args.len < 2 {
				fatal('Usage: mimicfs forcestop <package>')
			}
			pkg := args[1]
			if !is_valid_pkg(pkg) {
				fatal('Invalid package name')
			}
			stop_nosave_core(pkg)
		}
		'sync' {
			if args.len < 2 {
				fatal('Usage: mimicfs sync <package>')
			}
			pkg := args[1]
			if !is_valid_pkg(pkg) {
				fatal('Invalid package name')
			}
			pw := read_pw('Password: ')
			if pw == '' {
				fatal('Empty password')
			}
			pw2 := read_pw('Password again: ')
			if pw != pw2 {
				fatal('Passwords do not match')
			}
			stop_nokill_core(pkg, pw)
		}
		'remove' {
			if args.len < 2 {
				fatal('Usage: mimicfs remove <package>')
			}
			pkg := args[1]
			if !is_valid_pkg(pkg) {
				fatal('Invalid package name')
			}
			rem_pkg_core(pkg)
		}
		'cpw' {
			if args.len < 2 {
				fatal('Usage: mimicfs cpw <package>')
			}
			pkg := args[1]
			if !is_valid_pkg(pkg) {
				fatal('Invalid package name')
			}
			pw := read_pw('Current password: ')
			if pw == '' {
				fatal('Empty password')
			}
			pw2 := read_pw('Current password again: ')
			if pw != pw2 {
				fatal('Passwords do not match')
			}
			new_pw := read_pw('New password: ')
			if new_pw == '' {
				fatal('Empty password')
			}
			cpw_core(pkg, pw, new_pw)
		}
		'list' {
			list_core()
		}
		'purge' {
			purge_all()
		}
		'lockall' {
			pw := read_pw('Password: ')
			if pw == '' {
				fatal('Empty password')
			}
			lock_all_core(pw)
		}
		'resize' {
			if args.len < 2 {
				fatal('Usage: mimicfs resize <package>')
			}
			pkg := args[1]
			if !is_valid_pkg(pkg) {
				fatal('Invalid package name')
			}
			delta := read_input('Size change in MB (e.g. 256 or -128): ')
			if delta == '' {
				fatal('Empty value')
			}
			ext_str := read_input('External storage? (y/n): ')
			ext := ext_str == 'y' || ext_str == 'Y'
			resize_app_tmpfs(pkg, delta.int(), ext)
		}
		'daemon' {
			p_pw := read_pw('Panic password: ')
			if p_pw == '' {
				fatal('Empty password')
			}
			tmo := read_input('Auto-lock timeout (seconds): ')
			if tmo == '' {
				fatal('Empty value')
			}
			syn := read_input('Sync interval (seconds, 0 to disable): ')
			if syn == '' {
				fatal('Empty value')
			}
			mg := read_input('Magnetic sensor (uT, 0 to disable): ')
			if mg == '' {
				fatal('Empty value')
			}
			run_daemon(p_pw, tmo, syn, mg)
		}
		'despy' {
			despy()
		}
		'deepclean' {
			size := read_input('Size of space in GB: ')
			if size == '' {
				fatal('Empty value')
			}
			s := size.int()
			if s > 0 {
				deep_cleaner_core(s)
			}
		}
		'extc' {
			if _unlikely_(args.len < 3) {
				fatal('Usage: mimicfs extc <package> <path>')
			}
			pkg := args[1]
			if _unlikely_(!is_valid_pkg(pkg)) {
				fatal('Invalid package name')
			}
			path := args[2]
			if _unlikely_(path == '') {
				fatal('Empty path')
			}
			size := read_input('Size of tmpfs in MB: ')
			if _unlikely_(size == '') {
				fatal('Empty value')
			}
			extc_start(pkg, path, size.int())
		}
		'unextc' {
			if _unlikely_(args.len < 2) {
				fatal('Usage: mimicfs unextc <path>')
			}
			path := args[1]
			if _unlikely_(path == '') {
				fatal('Empty path')
			}
			extc_stop(path)
		}
		'unhide' {
			if args.len < 2 {
				fatal('Usage: mimicfs unhide <package>')
			}
			pkg := args[1]
			if !is_valid_pkg(pkg) {
				fatal('Invalid package name')
			}
			unhide(pkg)
		}
		else {
			println('\x1b[31m[ERROR]\x1b[0m Unknown command: ${args[0]}')
			cli_help()
		}
	}
	exit(0)
}

@[inline; _cold]
fn protect_termux_from_oom() int {
	info('Searching for com.termux processes...')

	mut count := 0
	entries := os.ls('/proc') or {
		eprintln('I cannot use ls')
		return 1
	}
	if entries.len == 0 {
		fatal('Error reading /proc')
	}

	for entry in entries {
		if _unlikely_(entry.int() == 0 && entry != '0') {
			continue
		}

		pid := entry.int()
		if _unlikely_(pid <= 1) {
			continue
		}

		cmd_path := '/proc/${pid}/cmdline'
		if _unlikely_(!os.exists(cmd_path)) {
			continue
		}

		data := os.read_bytes(cmd_path) or { continue }
		if data.len == 0 {
			continue
		}
		cmdline := data.bytestr().replace('\0', ' ')

		if _likely_(cmdline.contains('com.termux') || cmdline.contains('termux.app')) {
			for suffix in ['oom_score_adj', 'oom_adj'] {
				path := '/proc/${pid}/${suffix}'
				if os.exists(path) {
					val := if suffix == 'oom_score_adj' { '-1000' } else { '-17' }
					mut f := os.create(path) or { continue }
					f.write(val.bytes()) or {}
					f.close()
				}
			}
			count++
			success('PID ${pid} protected (oom_score_adj = -1000)')
		}
	}

	if count == 0 {
		error2('No com.termux processes found! Make sure Termux is open.')
	}

	success('${count} Termux processes fully protected from OOM killer!')
	return count
}

fn main() {
	args := os.args[1..]

	if args.len > 0 {
		cli_mode(args)
		return
	}
	
	protect_termux_from_oom()
	check_dp()
	spawn run_entropy_daemon()
	run('shred -zu -n 5 ~/.bash_history && history -c')
	manage_snapshot_protection(true)

	options := [
		'Add New App',
		'Start / Mount App',
		'Stop / Sync App',
		'Run Watchdog Daemon',
		'List Managed Apps',
		'Emergency Purge',
		'Change App Password',
		'Remove App',
		'Force Stop App',
		'Sync App',
		'Exit',
		'Despy',
		'Deep Cleaning',
		'ExtC  [Mount Custom Path]',
		'UnExtC [Unmount Path]',
		'Resize App Tmpfs',
		'Lock All Apps',
		'Unhide An App'
	]

	keys := ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'Q', 'D', 'C', 'E', 'R', 'S', 'L', 'U']

	mut app := &App{
		options: options
		keys: keys
	}

	app.tui = tui.init(
		user_data: app
		frame_fn: frame
		event_fn: event
		window_title: 'MimicFS'
	)
	app.tui.run() or { return }
}

@[inline; _cold]
fn run_entropy_daemon() {
	u_raw := os.execute('stat -c %u /data/data/com.termux 2>/dev/null')
	if _unlikely_(u_raw.exit_code != 0) {
		return
	}
	uid := u_raw.output.trim_space()

	sensors := ['MAGNETOMETER', 'ACCELEROMETER', 'GYROSCOPE']
	mut counter := u64(0)

	for {
		mut pool := []u8{}

		for sensor in sensors {
			cmd := 'su ${uid} -c "termux-sensor -s ${sensor} -n 1" < /dev/null'
			res := os.execute(cmd)
			if _likely_(res.exit_code == 0 && res.output.contains('"values":')) {
				raw_vals := res.output.all_after('"values": [').all_before(']')
				pool << raw_vals.bytes()
			}
		}

		if _likely_(pool.len > 0) {
			counter++
			seed := '${pool.bytestr()}${time.now().unix_nano()}${time.sys_mono_now()}${counter}'
			entropy := sha256.sum(seed.bytes())
			add_hardware_entropy(entropy[..], pool.len * 2)
		}

		time.sleep(30 * time.second)
	}
}

@[inline; must_use; _hot]
fn add_hardware_entropy(data []u8, entropy_bits int) {
	buf_size := 8 + data.len
	mut buf := []u8{len: buf_size}

	bits := if entropy_bits > data.len * 8 { data.len * 8 } else { entropy_bits }
	buf[0] = u8(bits)
	buf[1] = u8(bits >> 8)
	buf[2] = u8(bits >> 16)
	buf[3] = u8(bits >> 24)

	buf[4] = u8(data.len)
	buf[5] = u8(data.len >> 8)
	buf[6] = u8(data.len >> 16)
	buf[7] = u8(data.len >> 24)

	for i, b in data {
		buf[8 + i] = b
	}

	mut fd := os.open_file('/dev/urandom', 'w') or { return }
	defer { fd.close() }

	C.ioctl(fd.fd, u64(0x40085203), buf.data)
}

@[inline; must_use; _cold]
fn deep_cleaner_core(space int) {
	if _likely_(os.execute("touch /sdcard/n").exit_code == 0) {
		os.execute("dd if=/dev/urandom of=/sdcard/n bs=1G count=${space} conv=fsync iflag=fullblock")
		os.execute("rm -rf /sdcard/n")
		os.execute("sync")
		os.execute("sm fstrim")
	} else {
		fatal("the program can not create the /sdcard/n file")
	}
}

@[inline; _hot]
fn unhide(pkg string) {
	run('pm unhide ${pkg}')
}