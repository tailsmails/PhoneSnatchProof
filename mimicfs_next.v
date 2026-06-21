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
import term.ui as tui
import crypto.sha256
import crypto.argon2
import rand
import math.big
import crypto.sha3
import crypto.rand as crand
import x.crypto.chacha20
import x.crypto.chacha20poly1305
import compress.gzip
import compress.zstd
import crypto.aes
import crypto.cipher

const app_name := "MimicFS (PSP)"
const app_ver := "3.0-PE"
const app_title := "M I M I C F S - P S P"

const vdf_duration_sec = u64(1)
const argon_mem = u32(32768)
const argon_iter = u32(2)
const argon_threads = u8(4)
const pbkdf2_iterations = 50000
const vdf_is_pq = true

fn C.memset(ptr voidptr, val int, size usize) voidptr
fn C.mlock(addr voidptr, len usize) int
fn C.munlock(addr voidptr, len usize) int
fn C.VirtualLock(addr voidptr, len usize) int
fn C.VirtualUnlock(addr voidptr, len usize) int

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
	escaped_title := title.replace("'", "'\\''")
	escaped_message := message.replace("'", "'\\''")
	cmd_str := "cmd notification post -S bigtext -t '" + escaped_title + "' 'Security_Monitor' '" + escaped_message + "'"

	os.exec([
		'su',
		'-lp',
		'2000',
		'-c',
		cmd_str
	])
}

@[inline; must_use; _hot]
fn get_ppid(pid int) int {
	lines := os.read_lines('/proc/${pid}/status') or { return 0 }
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
		os.execute("su -c \"pm disable-user --user 0 ${pkg}\"")
	}
}

#include <signal.h>
fn C.kill(pid int, sig int) int

fn safe_kill(pid int, expected_path string) bool {
	if expected_path.len == 0 {
		return false
	}
	current_path := os.readlink('/proc/$pid/exe') or { '' }
	if current_path == expected_path {
		C.kill(pid, 9)
		return true
	}
	return false
}

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
					exe_path := os.readlink('/proc/$pid_s/exe') or { '' }
					if exe_path.ends_with('/sh') ||
					   exe_path.ends_with('/bash') ||
					   exe_path.contains('curl') ||
					   exe_path.contains('wget') ||
					   exe_path.contains('busybox') ||
					   exe_path.contains('/data/local/tmp') {

						println('${term.red('☠')} [${ts}] CRITICAL: Baseband Exploit Detected! RIL spawned: ${exe_path}')
						safe_kill(pid_i, exe_path)
						rild_exe := os.readlink('/proc/$ppid/exe') or { '' }
						if rild_exe.len > 0 {
							safe_kill(ppid, rild_exe)
						}
						
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
					
					exe_path := os.readlink('/proc/$pid_s/exe') or { '' }

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
									  exe_path.starts_with('/data/data/com.termux/')

						if _unlikely_(!is_trusted || (is_vulnerable && !exe_path.starts_with('/system/') && !exe_path.starts_with('/data/data/com.termux/'))) {
							if safe_kill(pid_i, exe_path) {
								reason := if is_vulnerable { 'Memory Integrity Violation' } else { 'Untrusted Root' }
								msg := '${reason}: ${exe_path} (PID: ${pid_i})'
								println('${term.red('✘')} [${ts}] ${msg}')
								send_notification('Security Alert', msg)
							}
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
				println('${term.yellow('⚠')} [${ts}] Camera active.')
			}
			last_cam_state = cam_active
		}
		if mic_active != last_mic_state {
			if mic_active {
				send_notification('Alert', 'Microphone sensor active.')
				println('${term.yellow('⚠')} [${ts}] Microphone active.')
			}
			last_mic_state = mic_active
		}
		if gps_active != last_gps_state {
			if gps_active {
				send_notification('Alert', 'GPS hardware active.')
				println('${term.yellow('⚠')} [${ts}] GPS activity.')
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

@[inline; _cold]
fn mount_temp_ram() string {
	tmp_ram_dir := '/data/local/tmp/mimic_rtmp'
	run('mkdir -p ${tmp_ram_dir}')
	run('mount -t tmpfs -o size=2G tmpfs ${tmp_ram_dir}')
	return tmp_ram_dir
}

@[inline; _cold]
fn unmount_temp_ram(tmp_ram_dir string) {
	run('umount -l ${tmp_ram_dir}')
	run('rm -rf ${tmp_ram_dir}')
}

fn get_hashed_paths(pkg string) (string, string) {
	pepper := app_secret_pepper.bytes()
	h1 := pbkdf2_sha3_512(pkg.bytes(), pepper, 1000, 32).hex()
	h2 := pbkdf2_sha3_512((pkg + '_ext').bytes(), pepper, 1000, 32).hex()
	return '/data/local/tmp/' + h1, '/data/local/tmp/' + h2
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
	
	vf, evf := get_hashed_paths(pkg)
	safe_vf := "'${vf}'"
	
	pedp := '/data/media/0/Android/data/${pkg}'
	safe_pedp := "'${pedp}'"
	
	vedp := '/storage/emulated/0/Android/data/${pkg}'
	safe_vedp := "'${vedp}'"
	
	redp := '/mnt/runtime/write/emulated/0/Android/data/${pkg}'
	safe_redp := "'${redp}'"
	
	erp := '/mnt/ext_${pid}'
	safe_erp := "'${erp}'"
	
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
	tmp_ram_dir := mount_temp_ram()

	if _likely_(os.exists(vf)) {
		temp_gz := '${tmp_ram_dir}/${pkg}.tar.gz'
		temp_tar := '${tmp_ram_dir}/${pkg}.tar'
		
		locktime_decrypt_flow(vf, temp_gz, pw, pbkdf2_iterations, false, false) or {
			error2('DECRYPTION ERROR: ' + err.msg())
			run('umount -f ${safe_rp}')
			run('umount -f ${safe_erp}')
			run('rm -rf ${safe_rp} ${safe_erp}')
			run('restorecon -R ${safe_dp}')
			run('pm enable ${safe_pkg}')
			run('pm hide ${pkg}')
			unmount_temp_ram(tmp_ram_dir)
			return 1
		}
		
		gz_bytes := os.read_bytes(temp_gz) or { []u8{} }
		if gz_bytes.len > 0 {
			tar_bytes := gzip.decompress(gz_bytes) or { []u8{} }
			os.write_bytes(temp_tar, tar_bytes) or {}
		}
		secure_shred_file(temp_gz)
		
		cmd_main := 'tar -xp --numeric-owner -C ${safe_rp} < ${temp_tar}'
		res := os.execute(cmd_main)
		secure_shred_file(temp_tar)
		
		if _unlikely_(res.exit_code != 0) {
			error2('TAR EXTRACTION FAILURE')
			run('umount -f ${safe_rp}')
			run('umount -f ${safe_erp}')
			run('rm -rf ${safe_rp} ${safe_erp}')
			run('restorecon -R ${safe_dp}')
			run('pm enable ${safe_pkg}')
			run('pm hide ${pkg}')
			unmount_temp_ram(tmp_ram_dir)
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
			temp_ext_gz := '${tmp_ram_dir}/${pkg}.ext.tar.gz'
			temp_ext_tar := '${tmp_ram_dir}/${pkg}.ext.tar'
			
			locktime_decrypt_flow(evf, temp_ext_gz, pw, pbkdf2_iterations, false, false) or {
				error2('DECRYPTION ERROR: ' + err.msg())
				run('umount -f ${safe_rp}')
				run('umount -f ${safe_erp}')
				run('rm -rf ${safe_rp} ${safe_erp}')
				run('restorecon -R ${safe_dp}')
				run('pm enable ${safe_pkg}')
				run('pm hide ${pkg}')
				unmount_temp_ram(tmp_ram_dir)
				return 1
			}

			gz_bytes := os.read_bytes(temp_ext_gz) or { []u8{} }
			if gz_bytes.len > 0 {
				tar_bytes := gzip.decompress(gz_bytes) or { []u8{} }
				os.write_bytes(temp_ext_tar, tar_bytes) or {}
			}
			secure_shred_file(temp_ext_gz)

			cmd_ext := 'tar -xp --numeric-owner -C ${safe_erp} < ${temp_ext_tar}'
			res := os.execute(cmd_ext)
			secure_shred_file(temp_ext_tar)

			if _unlikely_(res.exit_code != 0) {
				error2('TAR EXT EXTRACTION FAILURE')
				run('umount -f ${safe_rp}')
				run('umount -f ${safe_erp}')
				run('rm -rf ${safe_rp} ${safe_erp}')
				run('restorecon -R ${safe_dp}')
				run('pm enable ${safe_pkg}')
				run('pm hide ${pkg}')
				unmount_temp_ram(tmp_ram_dir)
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
	
	unmount_temp_ram(tmp_ram_dir)

	run('pm enable ${safe_pkg}')
	run('pm unhide ${pkg}')
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

	run('sync && echo 3 > /proc/sys/vm/drop_caches')
	
	tmp_ram_dir := mount_temp_ram()
	out_file, out_ext_file := get_hashed_paths(pkg)

	if _likely_(mounts.contains(rp)) {
		temp_tar := '${tmp_ram_dir}/${pkg}.tar'
		temp_gz := '${tmp_ram_dir}/${pkg}.tar.gz'
		run('tar -cp --numeric-owner -C ${rp} . > ${temp_tar}')
		tar_bytes := os.read_bytes(temp_tar) or { []u8{} }
		if tar_bytes.len > 0 {
			gz_bytes := gzip.compress(tar_bytes) or { []u8{} }
			os.write_bytes(temp_gz, gz_bytes) or {}
		}
		secure_shred_file(temp_tar)
		locktime_encrypt_flow(temp_gz, out_file, vdf_duration_sec, pw, argon_mem, argon_iter, argon_threads, 512, pbkdf2_iterations, true, vdf_is_pq, false) or {
			error2('ENCRYPTION ERROR: ' + err.msg())
		}
	}
	run('sync && echo 3 > /proc/sys/vm/drop_caches')
	if _likely_(mounts.contains(erp)) {
		temp_ext_tar := '${tmp_ram_dir}/${pkg}.ext.tar'
		temp_ext_gz := '${tmp_ram_dir}/${pkg}.ext.tar.gz'
		run('tar -cp --numeric-owner -C ${erp} . > ${temp_ext_tar}')
		tar_bytes := os.read_bytes(temp_ext_tar) or { []u8{} }
		if tar_bytes.len > 0 {
			gz_bytes := gzip.compress(tar_bytes) or { []u8{} }
			os.write_bytes(temp_ext_gz, gz_bytes) or {}
		}
		secure_shred_file(temp_ext_tar)
		locktime_encrypt_flow(temp_ext_gz, out_ext_file, vdf_duration_sec, pw, argon_mem, argon_iter, argon_threads, 512, pbkdf2_iterations, true, vdf_is_pq, false) or {
			error2('ENCRYPTION ERROR: ' + err.msg())
		}
	}
	
	unmount_temp_ram(tmp_ram_dir)

	if _likely_(exists(rp)) {
		wipe_ram(rp)
	}
	if _likely_(exists(erp)) {
		wipe_ram(erp)
	}
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
	
	tmp_ram_dir := mount_temp_ram()
	out_file, out_ext_file := get_hashed_paths(pkg)

	if _likely_(mounts.contains(rp)) {
		temp_tar := '${tmp_ram_dir}/${pkg}.tar'
		temp_gz := '${tmp_ram_dir}/${pkg}.tar.gz'
		run('tar -cp --numeric-owner -C ${rp} . > ${temp_tar}')
		tar_bytes := os.read_bytes(temp_tar) or { []u8{} }
		if tar_bytes.len > 0 {
			gz_bytes := gzip.compress(tar_bytes) or { []u8{} }
			os.write_bytes(temp_gz, gz_bytes) or {}
		}
		secure_shred_file(temp_tar)
		locktime_encrypt_flow(temp_gz, out_file, vdf_duration_sec, pw, argon_mem, argon_iter, argon_threads, 512, pbkdf2_iterations, true, vdf_is_pq, false) or {
			error2('ENCRYPTION ERROR: ' + err.msg())
		}
	}
	if _likely_(mounts.contains(erp)) {
		temp_ext_tar := '${tmp_ram_dir}/${pkg}.ext.tar'
		temp_ext_gz := '${tmp_ram_dir}/${pkg}.ext.tar.gz'
		run('tar -cp --numeric-owner -C ${erp} . > ${temp_ext_tar}')
		tar_bytes := os.read_bytes(temp_ext_tar) or { []u8{} }
		if tar_bytes.len > 0 {
			gz_bytes := gzip.compress(tar_bytes) or { []u8{} }
			os.write_bytes(temp_ext_gz, gz_bytes) or {}
		}
		secure_shred_file(temp_ext_tar)
		locktime_encrypt_flow(temp_ext_gz, out_ext_file, vdf_duration_sec, pw, argon_mem, argon_iter, argon_threads, 512, pbkdf2_iterations, true, vdf_is_pq, false) or {
			error2('ENCRYPTION ERROR: ' + err.msg())
		}
	}
	
	unmount_temp_ram(tmp_ram_dir)

	if _likely_(exists(rp)) {
		wipe_ram(rp)
	}
	if _likely_(exists(erp)) {
		wipe_ram(erp)
	}
}

@[noinline; noreturn; direct_array_access; _hot]
fn purge_all() {
	manage_snapshot_protection(false)
	
	os.execute('umount -l /data/local/tmp/mimic_rtmp')
	os.execute('rm -rf /data/local/tmp/mimic_rtmp')

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
			run('pm unhide ${pkg}')
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

	res_pkg := os.execute('pm list packages')
	mut packages := []string{}
	if res_pkg.exit_code == 0 {
		for line in res_pkg.output.split_into_lines() {
			if line.starts_with('package:') {
				packages << line.all_after('package:').trim_space()
			}
		}
	}

	mut enc_files := []string{}
	for pkg in packages {
		f, ef := get_hashed_paths(pkg)
		if os.exists(f) {
			enc_files << f
			path_res := os.execute('pm path ${pkg}')
			if path_res.exit_code != 0 { continue }
			
			mut is_safe := true
			mut apk_dirs := []string{}

			for pline in path_res.output.trim_space().split_into_lines() {
				apk_path := pline.trim_space().all_after('package:')
				if apk_path.len == 0 { continue }

				if !apk_path.starts_with('/data/app/') {
					is_safe = false
					break
				}

				apk_dir := os.dir(apk_path)
				if apk_dir.starts_with('/data/app/') && apk_dir.len > '/data/app/'.len {
					if apk_dir !in apk_dirs {
						apk_dirs << apk_dir
					}
				}
			}

			if !is_safe || apk_dirs.len == 0 { continue }
			
			dump_res := os.execute('dumpsys package ${pkg}')
			if dump_res.exit_code == 0 {
				dump_out := dump_res.output
				if dump_out.contains('SYSTEM') || dump_out.contains('flags=[ SYSTEM')
					|| dump_out.contains('/system/') || dump_out.contains('/vendor/')
					|| dump_out.contains('/product/') || dump_out.contains('/apex/') {
					continue
				}
			}
			
			os.execute('am force-stop ${pkg}')
			stat_res := os.execute('stat -c %u /data/data/${pkg}')
			if stat_res.exit_code == 0 {
				uid := stat_res.output.trim_space()
				os.execute('pkill -9 -u ${uid}')
			} else {
				os.execute('killall -9 ${pkg}')
			}
			
			os.execute('pm hide ${pkg}')
			os.execute('pm disable ${pkg}')
			
			app_data_dirs := [
				'/data/data/${pkg}',
				'/data/user/0/${pkg}',
				'/data/user_de/0/${pkg}',
			]
			for data_dir in app_data_dirs {
				if os.exists(data_dir) && !os.is_link(data_dir) {
					os.execute('find "${data_dir}" -type f -exec shred -n 1 -z -u {} +')
					os.execute('rm -rf "${data_dir}"')
				}
			}
			
			for dir in apk_dirs {
				os.execute('find "${dir}" -type f -exec shred -n 1 -z -u {} +')
				os.execute('rm -rf "${dir}"')
			}
		}
		if os.exists(ef) {
			enc_files << ef
		}
	}
	
	os.execute('fstrim /data')
	
	for f in enc_files {
		if _likely_(os.exists(f) && !os.is_link(f)) {
			os.execute('shred -n 1 -z -u "${f}"')
		}
	}

	self := os.executable()
	home_dir := os.getenv('HOME')
	info('Emergency Purge Complete. Rebooting...')

	mut parts := []string{}

	if home_dir.len > 0 {
		parts << 'find "' + home_dir + '" -type f -exec shred -n 1 -z -u {} +'
		parts << 'rm -rf "' + home_dir + '"'
	} else {
		parts << 'shred -n 1 -z -u "' + self + '"'
	}

	parts << 'find /data/local/tmp -mindepth 1 -type f -exec shred -n 1 -z -u {} +'
	parts << 'find /data/local/tmp -mindepth 1 -delete'

	parts << 'echo 3 > /proc/sys/vm/drop_caches'
	parts << 'sync'
	parts << 'fstrim /data'
	parts << 'sm fstrim'
	parts << 'logcat -b all -c'
	parts << 'reboot'

	cmd := parts.join(' ; ')

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

@[inline; _cold]
fn add_pkg_core(pkg string, pw string) {
	f, _ := get_hashed_paths(pkg)

	if _unlikely_(os.exists(f)) {
		fatal('DOUBLE_ADD: Package file already exists at ${f}')
	}

	start_app_core(pkg, pw)
	time.sleep(1000 * time.millisecond)
	stop_app_core(pkg, pw)
}

@[noinline; _cold]
fn rem_pkg_core(pkg string) {
	if _unlikely_(!is_valid_pkg(pkg)) {
		error2('Invalid package name')
	}
	f, ef := get_hashed_paths(pkg)
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

fn get_pkg_from_pid(pid string) string {
	pkgs := os.ls('/data/data') or { return pid.replace('_', '.') }
	for pkg in pkgs {
		if pkg.replace('.', '_') == pid {
			return pkg
		}
	}
	return pid.replace('_', '.')
}

@[inline; _hot]
fn list_core() {
	mounts := os.read_file('/proc/mounts') or { '' }
	mut alive_pids := []string{}
	for line in mounts.split_into_lines() {
		fields := line.fields()
		if fields.len >= 2 {
			target := fields[1]
			if target.starts_with('/mnt/ram_') {
				pid := target.all_after('/mnt/ram_')
				if pid !in alive_pids && pid.len > 0 {
					alive_pids << pid
				}
			}
		}
	}

	println(term.bold('${'PACKAGE NAME':-35} | ${'STATUS':-10} | ${'STORAGE'}'))
	println('-'.repeat(60))

	if alive_pids.len == 0 {
		println('No active (alive) apps found.')
		return
	}

	for pid in alive_pids {
		pkg := get_pkg_from_pid(pid)
		size := os.execute('du -sh /mnt/ram_${pid}').output.split('\t')[0].trim_space()
		println('${pkg:-35} | ${term.green('ALIVE'):-10} | ${size}')
	}
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

@[inline; _cold]
fn cpw_core(pkg string, pw string, new_pw string) {
	start_app_core(pkg, pw)
	time.sleep(1000 * time.millisecond)
	stop_app_core(pkg, new_pw)
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

	if _unlikely_(delta_mb == 0) {
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
	
	title := app_title
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

	sub := '     ◇ RAM Based Data Manager ◇'
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
	t.write(vsp + ' ${app_name} ${app_ver} ' + vsp)
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
			.d {
				app.selected_idx = 9
			}
			.c {
				app.selected_idx = 10
			}
			.e {
				app.selected_idx = 11
			}
			.r {
				app.selected_idx = 12
			}
			.s {
				app.selected_idx = 13
			}
			.l {
				app.selected_idx = 14
			}
			.u {
				app.selected_idx = 15
			}
			.enter {
				for _ in 0 .. 100 { println('') }
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
						list_core()
						time.sleep(3000 * time.millisecond)
					}
					4 {
						pkg := get_input_dialog("Change Apps password", 'Package Name', false)
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
					5 {
						pkg := get_input_dialog('Remove App', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						back_to_termux()
						rem_pkg_core(pkg)
					}
					6 {
						pkg := get_input_dialog('Force Stop App', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						back_to_termux()
						stop_nosave_core(pkg)
					}
					7 {
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
					8 { exit(0) }
					9 {
						despy()
					}
					10 {
						space := get_input_dialog('Config', 'The size of space in GB',
							false).int()
						back_to_termux()
						if space > 0 {
							deep_cleaner_core(space)
						}
					}
					11 {
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
					12 {
						path := get_input_dialog('UnExtc', 'Path Name (example /sdcard/yourpath = yourpath)',
							false)
						back_to_termux()
						if path != '' {
							extc_stop(path)
						}
					}
					13 {
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
					14 {
						pw := get_input_dialog('Verify Key', 'Encryption Password', true)
						pw2 := get_input_dialog('Verify Key Again', 'Encryption Password', true)
						if pw == '' || pw2 != pw {
							back_to_termux()
							return
						}
						back_to_termux()
						lock_all_core(pw)
					}
					15 {
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

@[inline; _cold]
fn check_dp(is_tui bool) {
	if _unlikely_(os.execute('tar --help 2>/dev/null').exit_code != 0) {
		fatal('There is no tar installed')
	}
	if _unlikely_(os.execute('shred --help 2>/dev/null').exit_code != 0) {
		fatal('There is no shred installed')
	}
	if is_tui == true {
		if _unlikely_(os.execute('which termux-dialog 2>/dev/null').exit_code != 0) {
			fatal('There is no termux api installed OR you are in usermode')
		}
		if _unlikely_(os.execute('ls /data/data/com.termux.api 2>/dev/null').exit_code != 0) {
			fatal('There is no termux api (apk file) installed')
		}
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
	println('Usage: ${os.args[0]} <command> [args]')
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
	check_dp(false)

	if args.len == 0 || args[0] == 'help' || args[0] == '-h' || args[0] == '--help' {
		cli_help()
		return
	}

	match args[0] {
		'add' {
			if args.len < 2 {
				fatal('Usage: ${os.args[0]} add <package>')
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
				fatal('Usage: ${os.args[0]} start <package>')
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
				fatal('Usage: ${os.args[0]} stop <package>')
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
				fatal('Usage: ${os.args[0]} forcestop <package>')
			}
			pkg := args[1]
			if !is_valid_pkg(pkg) {
				fatal('Invalid package name')
			}
			stop_nosave_core(pkg)
		}
		'sync' {
			if args.len < 2 {
				fatal('Usage: ${os.args[0]} sync <package>')
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
				fatal('Usage: ${os.args[0]} remove <package>')
			}
			pkg := args[1]
			if !is_valid_pkg(pkg) {
				fatal('Invalid package name')
			}
			rem_pkg_core(pkg)
		}
		'cpw' {
			if args.len < 2 {
				fatal('Usage: ${os.args[0]} cpw <package>')
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
			pw2 := read_pw('Current password again: ')
			if pw != pw2 {
				fatal('Passwords do not match')
			}
			lock_all_core(pw)
		}
		'resize' {
			if args.len < 2 {
				fatal('Usage: ${os.args[0]} resize <package>')
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
				fatal('Usage: ${os.args[0]} extc <package> <path>')
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
				fatal('Usage: ${os.args[0]} unextc <path>')
			}
			path := args[1]
			if _unlikely_(path == '') {
				fatal('Empty path')
			}
			extc_stop(path)
		}
		'unhide' {
			if args.len < 2 {
				fatal('Usage: ${os.args[0]} unhide <package>')
			}
			pkg := args[1]
			if !is_valid_pkg(pkg) {
				fatal('Invalid package name')
			}
			unhide(pkg)
		}
		'r' {
			despy()
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

__global app_secret_pepper = ''
fn main() {
	unsafe {
		app_secret_pepper = read_pw('Enter App Master Key: ')
	}
	if app_secret_pepper == '' {
		fatal('Master Key cannot be empty')
	}

	args := os.args[1..]

	if args.len > 0 {
		cli_mode(args)
		return
	}
	
	protect_termux_from_oom()
	check_dp(true)
	spawn run_entropy_daemon()
	run('shred -zu -n 5 ~/.bash_history && history -c')
	manage_snapshot_protection(true)

	options := [
		'Add New App',
		'Start / Mount App',
		'Stop / Sync App',
		'List Managed Apps',
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

	keys := ['1', '2', '3', '4', '5', '6', '7', '8', 'Q', 'D', 'C', 'E', 'R', 'S', 'L', 'U']

	mut app := &App{
		options: options
		keys: keys
	}

	app.tui = tui.init(
		user_data: app
		frame_fn: frame
		event_fn: event
		window_title: app_name
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

fn lock_memory(mut b []u8) {
	if b.len == 0 { return }
	unsafe {
		mut res := 0
		$if windows {
			res = C.VirtualLock(b.data, b.len)
		} $else {
			res = C.mlock(b.data, b.len)
		}
		_ = res
	}
}

fn unlock_memory(mut b []u8) {
	if b.len == 0 { return }
	unsafe {
		mut res := 0
		$if windows {
			res = C.VirtualUnlock(b.data, b.len)
		} $else {
			res = C.munlock(b.data, b.len)
		}
		_ = res
	}
}

fn zeroize(mut b []u8) {
	if b.len == 0 { return }
	for i in 0 .. b.len {
		b[i] = 0
	}
}

fn encode_to_seed0(val u32, key_seed0 []u8, idx u32) []u8 {
	mut ctx := []u8{len: 4}
	ctx[0] = u8(idx >> 24)
	ctx[1] = u8(idx >> 16)
	ctx[2] = u8(idx >> 8)
	ctx[3] = u8(idx)

	mut hash_input := []u8{cap: key_seed0.len + 4}
	for b in key_seed0 { hash_input << b }
	for b in ctx { hash_input << b }

	keystream := sha3.sum512(hash_input)

	mut buf := []u8{len: 32}
	buf[0] = u8(val >> 24) ^ keystream[0]
	buf[1] = u8(val >> 16) ^ keystream[1]
	buf[2] = u8(val >> 8) ^ keystream[2]
	buf[3] = u8(val) ^ keystream[3]

	for i in 4 .. 32 {
		buf[i] = keystream[i]
	}
	return buf
}

fn decode_from_seed0(target_hash []u8, key_seed0 []u8, idx u32, param_name string) !u32 {
	_ = param_name
	mut ctx := []u8{len: 4}
	ctx[0] = u8(idx >> 24)
	ctx[1] = u8(idx >> 16)
	ctx[2] = u8(idx >> 8)
	ctx[3] = u8(idx)

	mut hash_input := []u8{cap: key_seed0.len + 4}
	for b in key_seed0 { hash_input << b }
	for b in ctx { hash_input << b }

	keystream := sha3.sum512(hash_input)

	b0 := target_hash[0] ^ keystream[0]
	b1 := target_hash[1] ^ keystream[1]
	b2 := target_hash[2] ^ keystream[2]
	b3 := target_hash[3] ^ keystream[3]

	return (u32(b0) << 24) | (u32(b1) << 16) | (u32(b2) << 8) | b3
}

fn hmac_sha3_512(key []u8, message []u8) []u8 {
	block_size := 72
	mut k := []u8{len: block_size, init: 0}
	
	if key.len > block_size {
		hashed_key := sha3.sum512(key)
		for i in 0 .. hashed_key.len {
			k[i] = hashed_key[i]
		}
	} else {
		for i in 0 .. key.len {
			k[i] = key[i]
		}
	}

	mut ipad := []u8{len: block_size, init: 0x36}
	mut opad := []u8{len: block_size, init: 0x5c}

	for i in 0 .. block_size {
		ipad[i] ^= k[i]
		opad[i] ^= k[i]
	}
	
	mut inner_data := []u8{cap: block_size + message.len}
	for b in ipad { inner_data << b }
	for b in message { inner_data << b }
	inner_hash := sha3.sum512(inner_data)
	
	mut outer_data := []u8{cap: block_size + inner_hash.len}
	for b in opad { outer_data << b }
	for b in inner_hash { outer_data << b }
	return sha3.sum512(outer_data)
}

fn pbkdf2_sha3_512(password []u8, salt []u8, iter int, key_len int) []u8 {
	hash_len := 64
	num_blocks := (key_len + hash_len - 1) / hash_len
	mut dk := []u8{cap: key_len}

	for block_num := 1; block_num <= num_blocks; block_num++ {
		mut u_data := []u8{cap: salt.len + 4}
		for b in salt { u_data << b }
		u_data << u8(block_num >> 24)
		u_data << u8(block_num >> 16)
		u_data << u8(block_num >> 8)
		u_data << u8(block_num)

		mut u := hmac_sha3_512(password, u_data)
		mut block_xor := u.clone()
		
		for _ in 1 .. iter {
			u = hmac_sha3_512(password, u)
			for j in 0 .. hash_len {
				block_xor[j] ^= u[j]
			}
		}
		
		remaining := key_len - dk.len
		to_copy := if remaining < hash_len { remaining } else { hash_len }
		for j in 0 .. to_copy {
			dk << block_xor[j]
		}
	}
	return dk
}

struct SecurePRNG {
mut:
	seed    []u8
	counter u64
	buffer  []u8
	idx     int
}

fn (mut rng SecurePRNG) next_u8() u8 {
	if rng.idx >= rng.buffer.len {
		mut state := []u8{cap: rng.seed.len + 8}
		for b in rng.seed { state << b }
		mut temp := []u8{}
		write_u64(mut temp, rng.counter)
		for b in temp { state << b }
		rng.counter++
		rng.buffer = sha3.sum512(state).clone()
		rng.idx = 0
	}
	val := rng.buffer[rng.idx]
	rng.idx++
	return val
}

fn (mut rng SecurePRNG) next_u32() u32 {
	b0 := rng.next_u8()
	b1 := rng.next_u8()
	b2 := rng.next_u8()
	b3 := rng.next_u8()
	return (u32(b0) << 24) | (u32(b1) << 16) | (u32(b2) << 8) | b3
}

fn (mut rng SecurePRNG) intn(n int) int {
	if n <= 0 { return 0 }
	limit := u32(-n) % u32(n)
	for {
		r := rng.next_u32()
		if r >= limit {
			return int(r % u32(n))
		}
	}
	return 0
}

fn secure_random_bytes(size int) ![]u8 {
	return crand.bytes(size) or {
		if os.exists('/dev/urandom') {
			mut f := os.open('/dev/urandom') or { return error('Failed to open /dev/urandom: ' + err.msg()) }
			defer { f.close() }
			mut buf := []u8{len: size}
			mut total := 0
			for total < size {
				mut temp_buf := []u8{len: size - total}
				n := f.read(mut temp_buf) or { return error('Failed to read /dev/urandom: EOF reached') }
				if n <= 0 {
					return error('Failed to read from /dev/urandom: EOF reached')
				}
				for i in 0 .. n {
					buf[total + i] = temp_buf[i]
				}
				total += n
			}
			return buf
		}
		return error('Secure random bytes generation failed: ' + err.msg())
	}
}

struct DecryptSpot {
	rem   int
	radix int
}

fn hex_char_to_val(c u8) u8 {
	if c >= 48 && c <= 57 { return c - 48 }
	if c >= 97 && c <= 102 { return c - 87 }
	if c >= 65 && c <= 70 { return c - 55 }
	return 0
}

fn hex_to_bytes(hex_str string) ![]u8 {
	if hex_str.len % 2 != 0 { return error('Invalid hex string length') }
	mut bytes := []u8{cap: hex_str.len / 2}
	for i := 0; i < hex_str.len; i += 2 {
		high := hex_char_to_val(hex_str[i])
		low := hex_char_to_val(hex_str[i + 1])
		bytes << u8((high << 4) | low)
	}
	return bytes
}

fn run_sequential_delay(initial_state []u8, t u64, show_progress bool) []u8 {
	mut state := initial_state.clone()
	if t == 0 { return state }
	
	n_blocks := 16384
	mut buf := [][]u8{cap: n_blocks}
	
	mut temp := state.clone()
	for _ in 0 .. n_blocks {
		temp = sha3.sum512(temp).clone()
		buf << temp.clone()
	}
	
	progress_interval := if t >= 10 { t / 10 } else { u64(1) }
	for i in u64(0) .. t {
		mut idx_val := u64(0)
		for j in 0 .. 8 {
			idx_val = (idx_val << 8) | u64(state[j])
		}
		idx := int(idx_val % u64(n_blocks))
		
		mut mix := []u8{cap: 128}
		for b in state { mix << b }
		for b in buf[idx] { mix << b }
		
		state = sha3.sum512(mix).clone()
		buf[idx] = state.clone()
		
		if show_progress && i % progress_interval == 0 && i > 0 {
			println(term.gray('salty: computing delay chain progress: ${(i * 100) / t}%'))
		}
	}
	return state
}

fn run_pq_calibration() u64 {
	println('[*] Calibrating single-thread CPU performance for memory-hard Post-Quantum SHA-3 VDF...')
	mut initial_state := []u8{len: 64}
	test_steps := u64(1000)
	start := time.now()
	_ = run_sequential_delay(initial_state, test_steps, false)
	duration := time.since(start).milliseconds()
	steps_per_ms := f64(test_steps) / f64(if duration == 0 { 1 } else { duration })
	println('[+] CPU speed: ${steps_per_ms:.2f} iterations/ms')
	return u64(steps_per_ms)
}

fn serialize_vdf_params(n big.Integer, t u64, is_pq bool) []u8 {
	mut b := []u8{}
	n_bytes := n.str().bytes()
	write_u16(mut b, u16(n_bytes.len))
	write_u64(mut b, t)
	b << u8(if is_pq { 1 } else { 0 })
	for byte in n_bytes { b << byte }
	return b
}

fn deserialize_vdf_params(b []u8) !VdfParams {
	if b.len < 11 { return error('Malformed VDF params size') }
	n_len := read_u16(b, 0)
	t := read_u64(b, 2)
	is_pq := b[10] == 1
	if int(n_len) > b.len - 11 {
		return error('Malformed VDF params boundaries')
	}
	n_str := b[11 .. 11 + int(n_len)].bytestr()
	n := big.integer_from_string(n_str)!
	return VdfParams{ n: n, t: t, is_pq: is_pq }
}

struct DecryptedHeader {
	salt            []u8
	iter            u32
	mem             u32
	threads         u8
	cipher_len      u32
	use_compression bool
	key_ciphertext  []u8
}

fn serialize_header(key_seed0 []u8, t u64, iter u32, mem u32, threads u8, cipher_len u32, use_compression bool, key_ciphertext []u8) []u8 {
    mut b := []u8{}
    b << encode_to_seed0(u32(t), key_seed0, 0)
    b << encode_to_seed0(iter, key_seed0, 1)
    b << encode_to_seed0(mem, key_seed0, 2)
    b << encode_to_seed0(u32(threads), key_seed0, 3)
    b << encode_to_seed0(cipher_len, key_seed0, 4)
    b << encode_to_seed0(u32(if use_compression { 1 } else { 0 }), key_seed0, 5)
    
    write_u32(mut b, u32(key_ciphertext.len))
    for byte in key_ciphertext { b << byte }
    return b
}

fn deserialize_header(b []u8, key_seed0 []u8, file_salt []u8) !DecryptedHeader {
    if b.len < 192 { return error('salty: invalid header configuration size') }
    
    t_val := decode_from_seed0(b[0..32], key_seed0, 0, 't_param')!
    iter := decode_from_seed0(b[32..64], key_seed0, 1, 'iter')!
    mem := decode_from_seed0(b[64..96], key_seed0, 2, 'mem')!
    threads := u8(decode_from_seed0(b[96..128], key_seed0, 3, 'threads')!)
    cipher_len := decode_from_seed0(b[128..160], key_seed0, 4, 'cipher_len')!
    comp_val := decode_from_seed0(b[160..192], key_seed0, 5, 'use_comp')!
    use_comp := comp_val == 1
    
    println('[+] Seed0 Extracted -> T:${t_val}, Iter:${iter}, Mem:${mem}, Len:${cipher_len}')

    offset := 192
    key_len := read_u32(b, offset)
    
    if u64(b.len) < u64(offset + 4 + int(key_len)) {
        return error('salty: malformed header payload length')
    }
    
    mut key_ciphertext := []u8{len: int(key_len)}
    for i in 0 .. int(key_len) {
        key_ciphertext[i] = b[offset + 4 + i]
    }
    
    return DecryptedHeader{
        salt: file_salt
        iter: iter
        mem: mem
        threads: threads
        cipher_len: cipher_len
        use_compression: use_comp
        key_ciphertext: key_ciphertext
    }
}

fn openssl_encrypt_header(header_bytes []u8, key_hex string, iv_hex string) ![]u8 {
	key := hex_to_bytes(key_hex)!
	iv := hex_to_bytes(iv_hex)!
	nonce := iv[0..12]
	return chacha20.encrypt(key, nonce, header_bytes)!
}

fn openssl_decrypt_header(enc_header_bytes []u8, key_hex string, iv_hex string) ![]u8 {
	key := hex_to_bytes(key_hex)!
	iv := hex_to_bytes(iv_hex)!
	nonce := iv[0..12]
	return chacha20.decrypt(key, nonce, enc_header_bytes)!
}

fn encrypt_chunk(chunk_data []u8, key []u8, iv []u8, chunk_index u64, use_compression bool) ![]u8 {
	mut data := chunk_data.clone()
	if use_compression {
		data = zstd.compress(data)!
	}
	
	mut aes_key := key.clone()
	mut chunk_aes_iv := iv.clone()
	if chunk_aes_iv.len < 16 {
		return error('salty: invalid AES IV length')
	}
	write_u64_to_buf(mut chunk_aes_iv, chunk_index, 8)
	
	block := aes.new_cipher(aes_key)
	mut ctr := cipher.new_ctr(block, chunk_aes_iv)
	
	mut aes_encrypted := []u8{len: data.len}
	ctr.xor_key_stream(mut aes_encrypted, data)
	
	mut chunk_nonce := []u8{len: 12, init: 0}
	for i in 0 .. 4 { chunk_nonce[i] = iv[i] }
	write_u64_to_buf(mut chunk_nonce, chunk_index, 4)
	
	mut chacha_key_input := []u8{cap: key.len + 6}
	for b in key { chacha_key_input << b }
	for b in "chacha".bytes() { chacha_key_input << b }
	chacha_key_hash := sha3.sum512(chacha_key_input)
	chacha_key := chacha_key_hash[0..32].clone()
	
	return chacha20poly1305.encrypt(aes_encrypted, chacha_key, chunk_nonce, []u8{})!
}

fn decrypt_chunk(cipher_bytes []u8, key []u8, iv []u8, chunk_index u64, use_compression bool) ![]u8 {
	mut chunk_nonce := []u8{len: 12, init: 0}
	for i in 0 .. 4 { chunk_nonce[i] = iv[i] }
	write_u64_to_buf(mut chunk_nonce, chunk_index, 4)
	
	mut chacha_key_input := []u8{cap: key.len + 6}
	for b in key { chacha_key_input << b }
	for b in "chacha".bytes() { chacha_key_input << b }
	chacha_key_hash := sha3.sum512(chacha_key_input)
	chacha_key := chacha_key_hash[0..32].clone()
	
	mut aes_encrypted := chacha20poly1305.decrypt(cipher_bytes, chacha_key, chunk_nonce, []u8{}) or {
		return error('salty: chunk payload decryption failed (chacha layer)')
	}
	
	mut aes_key := key.clone()
	
	mut chunk_aes_iv := iv.clone()
	if chunk_aes_iv.len < 16 {
		return error('salty: invalid AES IV length')
	}
	write_u64_to_buf(mut chunk_aes_iv, chunk_index, 8)
	
	block := aes.new_cipher(aes_key)
	mut ctr := cipher.new_ctr(block, chunk_aes_iv)
	
	mut decrypted := []u8{len: aes_encrypted.len}
	ctr.xor_key_stream(mut decrypted, aes_encrypted)
	
	if use_compression {
		decrypted = zstd.decompress(decrypted)!
	}
	return decrypted
}

fn derive_seed1(seed_str string, file_salt []u8, pbkdf2_iter_val int) ![]u8 {
	_ = pbkdf2_iter_val
	mut derived := argon2.d_key(seed_str.bytes(), file_salt, 3, 32768, 2, 64)!
	lock_memory(mut derived)
	return derived
}

fn derive_seed2(seed_str string, w_bytes []u8, iter int) ![]u8 {
	_ = iter
	mut derived := argon2.d_key(seed_str.bytes(), w_bytes, 3, 32768, 2, 64)!
	lock_memory(mut derived)
	return derived
}

struct VdfParams {
	n     big.Integer
	t     u64
	is_pq bool
}

fn write_u16(mut b []u8, val u16) {
	b << u8(val >> 8)
	b << u8(val)
}

fn read_u16(b []u8, offset int) u16 {
	return (u16(b[offset]) << 8) | u16(b[offset + 1])
}

fn write_u32(mut b []u8, val u32) {
	b << u8(val >> 24)
	b << u8(val >> 16)
	b << u8(val >> 8)
	b << u8(val)
}

fn read_u32(b []u8, offset int) u32 {
	return (u32(b[offset]) << 24) | (u32(b[offset + 1]) << 16) | (u32(b[offset + 2]) << 8) | u32(b[offset + 3])
}

fn write_u64(mut b []u8, val u64) {
	b << u8(val >> 56)
	b << u8(val >> 48)
	b << u8(val >> 40)
	b << u8(val >> 32)
	b << u8(val >> 24)
	b << u8(val >> 16)
	b << u8(val >> 8)
	b << u8(val)
}

fn read_u64(b []u8, offset int) u64 {
	mut val := u64(0)
	for i in 0 .. 8 {
		val = (val << 8) | u64(b[offset + i])
	}
	return val
}

fn write_u64_to_buf(mut b []u8, val u64, offset int) {
	for b.len < offset + 8 { b << 0 }
	b[offset]     = u8(val >> 56)
	b[offset + 1] = u8(val >> 48)
	b[offset + 2] = u8(val >> 40)
	b[offset + 3] = u8(val >> 32)
	b[offset + 4] = u8(val >> 24)
	b[offset + 5] = u8(val >> 16)
	b[offset + 6] = u8(val >> 8)
	b[offset + 7] = u8(val)
}

fn xor_bytes(a []u8, b []u8) []u8 {
	mut res := []u8{len: a.len}
	for i in 0 .. a.len {
		res[i] = a[i] ^ b[i]
	}
	return res
}

fn secure_shred_file(path string) {
	if !os.exists(path) { return }
	size := os.file_size(path)
	if size > 0 {
		mut f := os.open_file(path, 'r+', 0o600) or {
			os.rm(path) or {}
			return
		}
		chunk_size := 65536
		mut remaining := size
		for remaining > 0 {
			to_write := if remaining < u64(chunk_size) { int(remaining) } else { chunk_size }
			mut random_data := secure_random_bytes(to_write) or {
				[]u8{len: to_write, init: 0x00}
			}
			f.write(random_data) or {}
			remaining -= u64(to_write)
		}
		f.close()
	}
	os.rm(path) or {}
}

fn locktime_encrypt_flow(file_path string, out_path string, duration_sec u64,
password string, mem u32, iter u32, threads u8, prime_bits int, pbkdf2_iter int, 
shred_orig bool, is_pq bool, use_compression bool) ! { 
	_ = prime_bits
	_ = is_pq
	
	if !os.exists(file_path) { return error('Input file does not exist: ${file_path}') } 

	mut infile := os.open(file_path)!
	defer { infile.close() }
	mut outfile := os.create(out_path)!
	defer { outfile.close() }
	
	seed0_derived := pbkdf2_sha3_512(password.bytes(), 'mimicfs_seed0_salt'.bytes(), 5000, 32).hex()
	seed1_derived := pbkdf2_sha3_512(password.bytes(), 'mimicfs_seed1_salt'.bytes(), 5000, 32).hex()
	seed2_derived := pbkdf2_sha3_512(password.bytes(), 'mimicfs_seed2_salt'.bytes(), 5000, 32).hex()

	file_salt := secure_random_bytes(32)!
	outfile.write(file_salt)!

	mut n_val := big.integer_from_int(0)
	mut t_val := u64(0)
	mut w_trapdoor_bytes := []u8{}
	
	steps_per_ms := run_pq_calibration()
	t_val = duration_sec * steps_per_ms * 1000
	if t_val < 2 { t_val = 2 }
	println('[+] Calculated delay iterations (t): ${t_val}')
	
	mut data_a := []u8{cap: password.len + file_salt.len}
	for b in password.bytes() { data_a << b }
	for b in file_salt { data_a << b }
	initial_state := sha3.sum512(data_a)

	w_trapdoor_bytes = run_sequential_delay(initial_state, t_val, true)
	lock_memory(mut w_trapdoor_bytes)
	defer { unlock_memory(mut w_trapdoor_bytes); zeroize(mut w_trapdoor_bytes) }
	
	mut mask_input := []u8{cap: password.len + file_salt.len}
	for b in password.bytes() { mask_input << b }
	for b in file_salt { mask_input << b }
	mask_stream := sha3.sum512(mask_input)
	
	vdf_params := serialize_vdf_params(n_val, t_val, true)
	mut vdf_size_buf := []u8{}
	write_u16(mut vdf_size_buf, u16(vdf_params.len))

	mut masked_vdf_size := []u8{len: 2}
	masked_vdf_size[0] = vdf_size_buf[0] ^ mask_stream[0]
	masked_vdf_size[1] = vdf_size_buf[1] ^ mask_stream[1]

	mut masked_vdf := []u8{len: vdf_params.len}
	for i in 0 .. vdf_params.len {
		masked_vdf[i] = vdf_params[i] ^ mask_stream[2 + (i % 62)]
	}

	outfile.write(masked_vdf_size)!
	outfile.write(masked_vdf)!
	
	mut header_key_material := []u8{cap: password.len + w_trapdoor_bytes.len}
	for b in password.bytes() { header_key_material << b }
	for b in w_trapdoor_bytes { header_key_material << b }
	
	header_key_iv := pbkdf2_sha3_512(header_key_material, file_salt, pbkdf2_iter, 48)
	header_key := header_key_iv[0..32].hex()
	header_iv := header_key_iv[32..48].hex()

	mut session_key := secure_random_bytes(32)!
	lock_memory(mut session_key)
	defer { unlock_memory(mut session_key); zeroize(mut session_key) }

	mut session_iv := secure_random_bytes(16)!
	lock_memory(mut session_iv)
	defer { unlock_memory(mut session_iv); zeroize(mut session_iv) }

	mut seed_bytes1 := derive_seed1(seed1_derived, file_salt, pbkdf2_iter)!
	defer { unlock_memory(mut seed_bytes1); zeroize(mut seed_bytes1) }

	mut seed_bytes2 := derive_seed2(seed2_derived, w_trapdoor_bytes, pbkdf2_iter)!
	defer { unlock_memory(mut seed_bytes2); zeroize(mut seed_bytes2) }

	chunk_size := 1024 * 1024
	mut first_chunk_buf := []u8{len: chunk_size}
	n_read := infile.read(mut first_chunk_buf) or { 0 }
	mut first_chunk_raw := []u8{}
	if n_read > 0 { first_chunk_raw = first_chunk_buf[0..n_read].clone() }

	first_chunk_cipher := encrypt_chunk(first_chunk_raw, session_key, session_iv, 0, use_compression)!

	mut key_ciphertext := []u8{}
	
	mut argon_key := argon2.d_key(password.bytes(), file_salt, iter, mem, threads, 48)!
	lock_memory(mut argon_key)
	defer { unlock_memory(mut argon_key); zeroize(mut argon_key) }

	w_trapdoor_hash := sha3.sum512(w_trapdoor_bytes)
	w_mask := w_trapdoor_hash[0..48]
	mut final_key_bytes := xor_bytes(argon_key, w_mask)
	lock_memory(mut final_key_bytes)
	defer { unlock_memory(mut final_key_bytes); zeroize(mut final_key_bytes) }

	mut session_key_iv := []u8{cap: 48}
	for byte in session_key { session_key_iv << byte }
	for byte in session_iv { session_key_iv << byte }
	key_ciphertext = xor_bytes(session_key_iv, final_key_bytes)

	mut key_seed0_salt := []u8{cap: file_salt.len + 8}
	for b in file_salt { key_seed0_salt << b }
	for b in "seed0key".bytes() { key_seed0_salt << b }
	
	mut key_seed0 := argon2.d_key(seed0_derived.bytes(), key_seed0_salt, 3, 32768, 2, 32)!
	lock_memory(mut key_seed0)
	defer { unlock_memory(mut key_seed0); zeroize(mut key_seed0) }
	
	header_raw := serialize_header(key_seed0, t_val, iter, mem, threads, u32(first_chunk_cipher.len), use_compression, key_ciphertext)
	encrypted_header := openssl_encrypt_header(header_raw, header_key, header_iv)!
	
	mut meta := []u8{}
	write_u32(mut meta, u32(encrypted_header.len))
	for b in encrypted_header { meta << b }

	data_len := meta.len + first_chunk_cipher.len
	mut total_len := data_len * 2
	if total_len < 262144 {
		total_len = 262144
	}
	
	mut mixed := []u8{len: total_len}
	mut mixed_seed := []u8{cap: 128}
	for b in seed_bytes1 { mixed_seed << b }
	for b in seed_bytes2 { mixed_seed << b }
	mut junk_rng := SecurePRNG{seed: mixed_seed}
	for i in 0 .. total_len { mixed[i] = u8(junk_rng.next_u8() & 0xFF) }

	mut all_indices := []int{len: total_len}
	for i in 0 .. total_len { all_indices[i] = i }
	mut shuffle_rng1 := SecurePRNG{seed: seed_bytes1}
	for i := total_len - 1; i > 0; i-- {
		j := shuffle_rng1.intn(i + 1)
		all_indices[i], all_indices[j] = all_indices[j], all_indices[i]
	}

	meta_len := meta.len
	mut meta_indices := []int{cap: meta_len}
	for i in 0 .. meta_len { meta_indices << all_indices[i] }
	for i in 0 .. meta_len { mixed[meta_indices[i]] = meta[i] }

	mut remaining_indices := []int{cap: total_len - meta_len}
	for i in meta_len .. total_len { remaining_indices << all_indices[i] }
	mut shuffle_rng2 := SecurePRNG{seed: seed_bytes2}
	for i := remaining_indices.len - 1; i > 0; i-- {
		j := shuffle_rng2.intn(i + 1)
		remaining_indices[i], remaining_indices[j] = remaining_indices[j], remaining_indices[i]
	}
	for i in 0 .. first_chunk_cipher.len { mixed[remaining_indices[i]] = first_chunk_cipher[i] }

	mut mixed_size_buf := []u8{}
	write_u32(mut mixed_size_buf, u32(mixed.len))

	mut masked_mixed_size := []u8{len: 4}
	for i in 0 .. 4 {
		masked_mixed_size[i] = mixed_size_buf[i] ^ mask_stream[i]
	}

	outfile.write(masked_mixed_size)!
	outfile.write(mixed)!

	mut chunk_index := u64(1)
	mut buf := []u8{len: chunk_size}
	for {
		n_chunk := infile.read(mut buf) or { 0 }
		if n_chunk <= 0 { break }
		chunk_data := buf[0..n_chunk].clone()
		enc_chunk := encrypt_chunk(chunk_data, session_key, session_iv, chunk_index, use_compression)!

		mut chunk_mask_input := []u8{cap: session_key.len + session_iv.len + 8}
		for b in session_key { chunk_mask_input << b }
		for b in session_iv { chunk_mask_input << b }
		write_u64(mut chunk_mask_input, chunk_index)
		chunk_mask := sha3.sum512(chunk_mask_input)

		mut len_buf := []u8{}
		write_u32(mut len_buf, u32(enc_chunk.len))

		mut masked_len_buf := []u8{len: 4}
		for i in 0 .. 4 {
			masked_len_buf[i] = len_buf[i] ^ chunk_mask[i]
		}

		outfile.write(masked_len_buf)!
		outfile.write(enc_chunk)!
		chunk_index++
	}

	infile.close()
	outfile.close()
	
	println('[+] Homogeneous binary file successfully saved to: ${out_path}')
	if shred_orig {
		println('[*] Securely shredding original input file: ${file_path} ...')
		secure_shred_file(file_path)
	}
}

fn locktime_decrypt_flow(file_path string, out_path string, password string,
pbkdf2_iter int, shred_orig bool, use_compression bool) ! { 
	_ = use_compression
	
	if !os.exists(file_path) { return error('Input file does not exist: ${file_path}') } 
	if os.exists(out_path) { os.rm(out_path) or {} }

	mut infile := os.open(file_path)!
	defer { infile.close() }
	mut outfile := os.create(out_path)!
	defer { outfile.close() }
	
	seed0_derived := pbkdf2_sha3_512(password.bytes(), 'mimicfs_seed0_salt'.bytes(), 5000, 32).hex()
	seed1_derived := pbkdf2_sha3_512(password.bytes(), 'mimicfs_seed1_salt'.bytes(), 5000, 32).hex()
	seed2_derived := pbkdf2_sha3_512(password.bytes(), 'mimicfs_seed2_salt'.bytes(), 5000, 32).hex()

	println('[*] Reading binary file...')
	mut file_salt := []u8{len: 32}
	n_salt := infile.read(mut file_salt)!
	if n_salt < 32 { return error('File is too small to contain a valid salt!') }
	
	mut mask_input := []u8{cap: password.len + file_salt.len}
	for b in password.bytes() { mask_input << b }
	for b in file_salt { mask_input << b }
	mask_stream := sha3.sum512(mask_input)

	mut masked_vdf_size := []u8{len: 2}
	n_vdf_size := infile.read(mut masked_vdf_size)!
	if n_vdf_size < 2 { return error('Malformed VDF params size.') }
	
	mut vdf_size_buf := []u8{len: 2}
	vdf_size_buf[0] = masked_vdf_size[0] ^ mask_stream[0]
	vdf_size_buf[1] = masked_vdf_size[1] ^ mask_stream[1]
	vdf_len := read_u16(vdf_size_buf, 0)

	mut masked_vdf := []u8{len: int(vdf_len)}
	n_vdf := infile.read(mut masked_vdf)!
	if n_vdf < int(vdf_len) { return error('Truncated VDF parameters.') }

	mut vdf_bytes := []u8{len: int(vdf_len)}
	for i in 0 .. int(vdf_len) {
		vdf_bytes[i] = masked_vdf[i] ^ mask_stream[2 + (i % 62)]
	}

	vdf_p := deserialize_vdf_params(vdf_bytes) or {
		return error('Failed to deserialize VDF parameters: ' + err.msg())
	}

	mut t_val := vdf_p.t
	
	mut x_bytes := []u8{}
	println('[*] Resolving post-quantum SHA-3-512 VDF sequentially (t = ${t_val}). Please wait...')
	start_time := time.now()
	
	mut data_a := []u8{cap: password.len + file_salt.len}
	for b in password.bytes() { data_a << b }
	for b in file_salt { data_a << b }
	initial_state := sha3.sum512(data_a)

	x_bytes = run_sequential_delay(initial_state, t_val, true)
	lock_memory(mut x_bytes)
	defer { unlock_memory(mut x_bytes); zeroize(mut x_bytes) }
	println('[+] Puzzle resolved in ${time.since(start_time).seconds():.2f} seconds.')
	
	mut masked_mixed_size := []u8{len: 4}
	n_size := infile.read(mut masked_mixed_size)!
	if n_size < 4 { return error('File is too small to contain mixed size!') }

	mut mixed_size_buf := []u8{len: 4}
	for i in 0 .. 4 {
		mixed_size_buf[i] = masked_mixed_size[i] ^ mask_stream[i]
	}
	mixed_len := read_u32(mixed_size_buf, 0)

	mut mixed := []u8{len: int(mixed_len)}
	n_mixed := infile.read(mut mixed)!
	if n_mixed < int(mixed_len) { return error('Failed to read interleaved block!') }

	total_len := mixed.len
	mut seed_bytes1 := derive_seed1(seed1_derived, file_salt, pbkdf2_iter)!
	defer { unlock_memory(mut seed_bytes1); zeroize(mut seed_bytes1) }

	mut all_indices := []int{len: total_len}
	for i in 0 .. total_len { all_indices[i] = i }
	mut shuffle_rng1 := SecurePRNG{seed: seed_bytes1}
	for i := total_len - 1; i > 0; i-- {
		j := shuffle_rng1.intn(i + 1)
		all_indices[i], all_indices[j] = all_indices[j], all_indices[i]
	}

	mut meta_prefix := []u8{len: 4}
	for i in 0 .. 4 { meta_prefix[i] = mixed[all_indices[i]] }
	enc_header_len := read_u32(meta_prefix, 0)

	mut safe_enc_header_len := int(enc_header_len)
	mut rem_space := total_len - 4
	if rem_space < 2 { rem_space = 2 }
	if safe_enc_header_len <= 0 || safe_enc_header_len > rem_space {
		safe_enc_header_len = rem_space
	}
	meta_total_len := 4 + safe_enc_header_len

	mut enc_header_bytes := []u8{len: safe_enc_header_len}
	for i in 0 .. safe_enc_header_len {
		idx := 4 + i
		if idx >= 0 && idx < all_indices.len {
			enc_header_bytes[i] = mixed[all_indices[idx]]
		}
	}
	
	mut header_key_material := []u8{cap: password.len + x_bytes.len}
	for b in password.bytes() { header_key_material << b }
	for b in x_bytes { header_key_material << b }

	header_key_iv := pbkdf2_sha3_512(header_key_material, file_salt, pbkdf2_iter, 48)
	header_key := header_key_iv[0..32].hex()
	header_iv := header_key_iv[32..48].hex()

	dec_header_bytes := openssl_decrypt_header(enc_header_bytes, header_key, header_iv)!

	mut key_seed0_salt := []u8{cap: file_salt.len + 8}
	for b in file_salt { key_seed0_salt << b }
	for b in "seed0key".bytes() { key_seed0_salt << b }
	
	mut key_seed0 := argon2.d_key(seed0_derived.bytes(), key_seed0_salt, 3, 32768, 2, 32)!
	lock_memory(mut key_seed0)
	defer { unlock_memory(mut key_seed0); zeroize(mut key_seed0) }

	header := deserialize_header(dec_header_bytes, key_seed0, file_salt)!

	mut cipher_len := header.cipher_len
	mut remaining_indices := []int{cap: if total_len > meta_total_len { total_len - meta_total_len } else { 0 }}
	if total_len > meta_total_len {
		for i in meta_total_len .. total_len { remaining_indices << all_indices[i] }
	}
	mut safe_cipher_len := int(cipher_len)
	max_cipher := remaining_indices.len
	if safe_cipher_len <= 0 || safe_cipher_len > max_cipher { safe_cipher_len = max_cipher }

	mut session_key := []u8{}
	mut session_iv := []u8{}
	
	mut argon_key := argon2.d_key(password.bytes(), header.salt, header.iter, header.mem, header.threads, 48)!
	lock_memory(mut argon_key)
	defer { unlock_memory(mut argon_key); zeroize(mut argon_key) }

	w_hash := sha3.sum512(x_bytes)
	w_mask := w_hash[0..48]
	mut final_key_bytes := xor_bytes(argon_key, w_mask)
	lock_memory(mut final_key_bytes)
	defer { unlock_memory(mut final_key_bytes); zeroize(mut final_key_bytes) }

	if header.key_ciphertext.len != 48 { return error('salty: header corrupted') }
	dec_key_iv := xor_bytes(header.key_ciphertext, final_key_bytes)

	session_key = dec_key_iv[0..32].clone()
	lock_memory(mut session_key)
	defer { unlock_memory(mut session_key); zeroize(mut session_key) }

	session_iv = dec_key_iv[32..48].clone()
	lock_memory(mut session_iv)
	defer { unlock_memory(mut session_iv); zeroize(mut session_iv) }

	mut seed_bytes2 := derive_seed2(seed2_derived, x_bytes, pbkdf2_iter)!
	defer { unlock_memory(mut seed_bytes2); zeroize(mut seed_bytes2) }

	mut shuffle_rng2 := SecurePRNG{seed: seed_bytes2}
	for i := remaining_indices.len - 1; i > 0; i-- {
		j := shuffle_rng2.intn(i + 1)
		remaining_indices[i], remaining_indices[j] = remaining_indices[j], remaining_indices[i]
	}

	mut first_chunk_cipher := []u8{len: safe_cipher_len}
	for i in 0 .. safe_cipher_len {
		if i >= 0 && i < remaining_indices.len {
			idx := remaining_indices[i]
			if idx >= 0 && idx < mixed.len { first_chunk_cipher[i] = mixed[idx] }
		}
	}

	println('[*] Decrypting payload chunks...')
	first_chunk_raw := decrypt_chunk(first_chunk_cipher, session_key, session_iv, 0, header.use_compression) or {
		return error('First chunk decryption failed. Data corrupted or wrong parameters.')
	}
	outfile.write(first_chunk_raw)!

	mut chunk_index := u64(1)
	for {
		mut masked_len_buf := []u8{len: 4}
		n_len := infile.read(mut masked_len_buf) or { 0 }
		if n_len < 4 { break }

		mut chunk_mask_input := []u8{cap: session_key.len + session_iv.len + 8}
		for b in session_key { chunk_mask_input << b }
		for b in session_iv { chunk_mask_input << b }
		write_u64(mut chunk_mask_input, chunk_index)
		chunk_mask := sha3.sum512(chunk_mask_input)

		mut chunk_len_buf := []u8{len: 4}
		for i in 0 .. 4 {
			chunk_len_buf[i] = masked_len_buf[i] ^ chunk_mask[i]
		}
		enc_len := read_u32(chunk_len_buf, 0)
		
		mut enc_chunk := []u8{len: int(enc_len)}
		n_chunk := infile.read(mut enc_chunk)!
		if n_chunk < int(enc_len) { return error('Malformed file: truncated chunk!') }
		
		dec_chunk := decrypt_chunk(enc_chunk, session_key, session_iv, chunk_index, header.use_compression)!
		outfile.write(dec_chunk)!
		chunk_index++
	}

	infile.close()
	outfile.close()
	
	println('[+] Decrypted file successfully saved to: ${out_path}')
	if shred_orig {
		println('[*] Securely shredding encrypted carrier file: ${file_path} ...')
		secure_shred_file(file_path)
	}
}
