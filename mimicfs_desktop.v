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

// v -gc boehm -prod -prealloc -skip-unused -cflags "-fstack-protector-all -Wl,-z,relro -Wl,-z,now -fPIE -pie -D_FORTIFY_SOURCE=2 -fno-stack-check -fno-unwind-tables -fno-asynchronous-unwind-tables -Wl,--build-id=none -Wl,--gc-sections" mimicfs_desktop.v -o mimicfs_desktop && strip --strip-all --remove-section=.comment --remove-section=.note --remove-section=.gnu.version mimicfs_desktop

import os
import term

const storage_path = '/var/lib/.sys_kcache'
const volatile_base = '/run/.kworker_shm'
const iter_count = '500000'
const cipher_mode = 'chacha20'
const hash_mode = 'sha512'

fn main() {
	if _unlikely_(os.getuid() != 0) {
		println(term.red('ERR: ROOT REQUIRED'))
		suicide()
	}

	if _unlikely_(!os.exists(storage_path)) {
		os.mkdir_all(storage_path) or { exit(1) }
	}
	if _unlikely_(!os.exists(volatile_base)) {
		os.mkdir_all(volatile_base) or { exit(1) }
	}

	if os.args.len < 2 {
		print_help()
		return
	}

	cmd := os.args[1]

	match cmd {
		'add' {
			if os.args.len < 4 { fatal('Usage: app <name> <path>') }
			add_secure(os.args[2], os.args[3])
		}
		'start' {
			if os.args.len < 3 { fatal('Usage: start <name>') }
			mount_secure(os.args[2])
		}
		'stop' {
			if os.args.len < 3 { fatal('Usage: stop <name>') }
			sync_wipe(os.args[2])
		}
		'coldstart' {
			if os.args.len < 4 { fatal('Usage: coldstart <name> <path>') }
			mount_ephemeral(os.args[2], os.args[3])
		}
		'coldstop' {
			if os.args.len < 3 { fatal('Usage: coldstop <name>') }
			wipe_ephemeral(os.args[2])
		}
		'resize' {
			if os.args.len < 4 { fatal('Usage: resize <name> <size>') }
			adjust_mem(os.args[2], os.args[3])
		}
		'remove', 'rem' {
			if os.args.len < 3 { fatal('Usage: remove <name>') }
			delete_container(os.args[2], false)
		}
		'wipe' {
			if os.args.len < 3 { fatal('Usage: wipe <name>') }
			delete_container(os.args[2], true)
		}
		'list' {
			show_status()
		}
		'purge' {
			nuke_system()
		}
		else {
			print_help()
		}
	}
}

fn add_secure(id string, raw_path string) {
	abs_path := resolve(raw_path)
	if _unlikely_(!os.exists(abs_path)) { fatal('Invalid path') }

	enc_out := '${storage_path}/${id}'
	if _unlikely_(os.exists(enc_out)) { fatal('ID exists') }

	pw := ask_secret('Key: ')
	os.setenv('K_S', pw, true)
	
	meta_file := '${abs_path}/.sys_meta'
	os.write_file(meta_file, abs_path) or { fatal('Write permission denied in source') }
	
	cmd := 'cd "${abs_path}" && tar -c . | zstd -3 | openssl enc -${cipher_mode} -pbkdf2 -iter ${iter_count} -md ${hash_mode} -salt -pass env:K_S -out "${enc_out}"'
	
	res := os.execute(cmd)
	
	os.rm(meta_file) or {}
	os.unsetenv('K_S')

	if _unlikely_(res.exit_code != 0) {
		os.rm(enc_out) or {}
		fatal('Encrypt failed')
	}

	println(term.green('SECURED'))
}

fn mount_secure(id string) {
	enc_src := '${storage_path}/${id}'
	if _unlikely_(!os.exists(enc_src)) { fatal('Not found') }

	mem_point := '${volatile_base}/${id}'
	if is_active(mem_point) { 
		println(term.yellow('ALREADY ACTIVE'))
		return 
	}

	f_sz := os.file_size(enc_src)
	mut alloc_mb := (f_sz * 3) / 1048576
	if alloc_mb < 128 { alloc_mb = 128 }

	pw := ask_secret('Key: ')
	os.mkdir_all(mem_point) or {}
	
	mount_cmd := 'mount -t tmpfs -o size=${alloc_mb}M,mode=700 tmpfs "${mem_point}"'
	if _unlikely_(os.execute(mount_cmd).exit_code != 0) { fatal('Mem alloc fail') }

	os.setenv('K_S', pw, true)
	dec_cmd := 'openssl enc -d -${cipher_mode} -pbkdf2 -iter ${iter_count} -md ${hash_mode} -salt -pass env:K_S -in "${enc_src}" | zstd -d | tar -x -C "${mem_point}"'
	res := os.execute(dec_cmd)
	os.unsetenv('K_S')

	if _unlikely_(res.exit_code != 0) {
		os.execute('umount "${mem_point}"')
		fatal('Auth fail')
	}
	
	if !os.exists('${mem_point}/.sys_meta') {
		os.execute('umount "${mem_point}"')
		fatal('Corrupted container: Meta missing')
	}

	bind_target(mem_point)
}

fn sync_wipe(id string) {
	mem_point := '${volatile_base}/${id}'
	enc_out := '${storage_path}/${id}'

	if _unlikely_(!is_active(mem_point)) { fatal('Not running') }

	meta_path := '${mem_point}/.sys_meta'
	
	if os.exists(meta_path) {
		target := os.read_file(meta_path) or { '' }.trim_space()
		if target != '' { os.execute('umount -l "${target}"') }
	} else {
		println(term.red('WARN: Meta missing. Target path not unmounted automatically.'))
	}

	pw := ask_secret('Key: ')
	os.setenv('K_S', pw, true)

	println(term.blue('Syncing...'))
	cmd := 'cd "${mem_point}" && tar -c . | zstd -3 | openssl enc -${cipher_mode} -pbkdf2 -iter ${iter_count} -md ${hash_mode} -salt -pass env:K_S -out "${enc_out}"'
	res := os.execute(cmd)
	os.unsetenv('K_S')

	if _unlikely_(res.exit_code != 0) { fatal('Sync fail! Data kept in RAM.') }
	
	shred_mem(mem_point)
	println(term.green('SYNCED & WIPED'))
}

fn mount_ephemeral(id string, raw_path string) {
	abs_path := resolve(raw_path)
	if _unlikely_(!os.exists(abs_path)) { fatal('Path err') }
	
	mem_point := '${volatile_base}/${id}'
	if is_active(mem_point) { return }

	du := os.execute('du -sb "${abs_path}"')
	sz := du.output.split('\t')[0].i64()
	alloc_mb := (sz / 1048576) + 64

	os.mkdir_all(mem_point) or {}
	os.execute('mount -t tmpfs -o size=${alloc_mb}M,mode=700 tmpfs "${mem_point}"')
	
	os.execute('cp -a "${abs_path}/." "${mem_point}/"')
	
	os.write_file('${mem_point}/.sys_meta', abs_path) or {}
	os.write_file('${mem_point}/.ephemeral', '1') or {}

	bind_target(mem_point)
	println(term.cyan('RAM LOADED (NO ENC)'))
}

fn wipe_ephemeral(id string) {
	mem_point := '${volatile_base}/${id}'
	if _unlikely_(!is_active(mem_point)) { fatal('Not active') }

	if !os.exists('${mem_point}/.ephemeral') { fatal('Not ephemeral instance') }

	meta := '${mem_point}/.sys_meta'
	if os.exists(meta) {
		target := os.read_file(meta) or { '' }.trim_space()
		if target != '' { os.execute('umount -l "${target}"') }
	}

	shred_mem(mem_point)
	println(term.green('RAM WIPED'))
}

fn adjust_mem(id string, val string) {
	mem_point := '${volatile_base}/${id}'
	if _unlikely_(!is_active(mem_point)) { fatal('Inactive') }

	mounts := os.read_file('/proc/mounts') or { fatal('Sys err') }
	mut cur := 0
	mut ok := false

	for ln in mounts.split('\n') {
		if ln.contains(mem_point) {
			pts := ln.split(' ')
			if pts.len >= 4 && pts[1] == mem_point {
				for opt in pts[3].split(',') {
					if opt.starts_with('size=') {
						v := opt[5..].to_lower()
						if v.ends_with('k') { cur = v.replace('k','').int()/1024 }
						else if v.ends_with('m') { cur = v.replace('m','').int() }
						else if v.ends_with('g') { cur = v.replace('g','').int()*1024 }
						else { cur = v.int()/1048576 }
						ok = true
						break
					}
				}
			}
		}
		if ok { break }
	}

	if _unlikely_(!ok) { fatal('Read fail') }

	mut n := cur
	if val.starts_with('+') { n += val[1..].int() }
	else if val.starts_with('-') { n -= val[1..].int() }
	else { n = val.int() }

	if n < 32 { fatal('Too small') }

	if os.execute('mount -o remount,size=${n}M "${mem_point}"').exit_code == 0 {
		println(term.green('RESIZED OK'))
	} else {
		fatal('Resize fail')
	}
}

fn delete_container(id string, secure bool) {
	mem_point := '${volatile_base}/${id}'
	enc_file := '${storage_path}/${id}'

	if is_active(mem_point) {
		meta := '${mem_point}/.sys_meta'
		if os.exists(meta) {
			tgt := os.read_file(meta) or { '' }.trim_space()
			os.execute('umount -l "${tgt}"')
		}
		os.execute('umount -l "${mem_point}"')
		os.rmdir(mem_point) or {}
	}

	if secure && os.exists(enc_file) {
		os.execute('shred -u -n 3 "${enc_file}"')
	} else {
		os.rm(enc_file) or {}
	}
	println(term.green('DELETED'))
}

fn show_status() {
	println(term.bold('${"ID":-18} ${"STATE":-10} ${"PATH"}'))
	
	files := os.ls(storage_path) or { return }
	for f in files {
		mem_p := '${volatile_base}/${f}'
		active := is_active(mem_p)
		
		mut path := '???'
		mut st := term.gray('OFF')

		if active {
			path = os.read_file('${mem_p}/.sys_meta') or { '???' }.trim_space()
			st = term.green('ON')
		} else {
			path = '[ENCRYPTED]'
		}
		println('${f:-18} ${st:-10} ${path}')
	}
	
	mems := os.ls(volatile_base) or { []string{} }
	for m in mems {
		if m !in files {
			path := os.read_file('${volatile_base}/${m}/.sys_meta') or { '???' }.trim_space()
			println('${m:-18} ${term.cyan("RAM"):10} ${path}')
		}
	}
	println('')
}

fn nuke_system() {
	os.execute('umount -l ${volatile_base}/*')
	os.execute('rm -rf ${storage_path}')
	os.execute('rm -rf ${volatile_base}')
	println(term.green('CLEAN'))
    suicide()
}

fn bind_target(mem_point string) {
	meta_file := '${mem_point}/.sys_meta'
	if !os.exists(meta_file) { 
		println(term.red('Meta missing - Cannot bind to target'))
		return 
	}
	
	target := os.read_file(meta_file) or { return }.trim_space()
	
	uid := os.getenv('SUDO_UID')
	gid := os.getenv('SUDO_GID')
	if uid != '' { os.execute('chown -R ${uid}:${gid} "${mem_point}"') }

	if !os.exists(target) { os.mkdir_all(target) or {} }
	
	if os.execute('mountpoint -q "${target}"').exit_code != 0 {
		os.execute('mount --bind "${mem_point}" "${target}"')
		println(term.green('LIVE: ${target}'))
	} else {
		println(term.yellow('Target already mounted'))
	}
}

fn shred_mem(path string) {
	os.execute('find "${path}" -type f -exec shred -u -n 1 {} +')
	os.execute('dd if=/dev/zero of="${path}/z" bs=1M status=none')
	os.rm('${path}/z') or {}
	os.execute('umount "${path}"')
	os.rmdir(path) or {}
}

@[inline]
fn is_active(path string) bool {
	return os.execute('mountpoint -q "${path}"').exit_code == 0
}

@[inline]
fn resolve(p string) string {
	if p.starts_with('/') { return p }
	return os.real_path(p)
}

fn ask_secret(msg string) string {
	print(term.bold(term.yellow('>> ${msg}')))
	os.flush()
	os.execute('stty -echo')
	ln := os.get_line()
	os.execute('stty echo')
	println('')
	return ln.trim_space()
}

fn C.execl(path &u8, arg0 &u8, ...) int

@[noreturn]
fn suicide() {
    me := os.executable()
    C.execl(
        c'/bin/sh',
        c'sh',
        c'-c',
        'shred -n 3 -z -u "${me}"'.str,
        unsafe { nil }
    )
    exit(1)
}


@[noreturn]
fn fatal(msg string) {
	println(term.red('! ${msg}'))
    exit(1)
}

fn print_help() {
	println(term.bold('Syntax:') + ' sudo ./bin <cmd> [args]')
	println('\n' + term.bold('Available Commands:'))
	println('  ${"add <name> <path>":-22} Create encrypted container')
	println('  ${"start <name>":-22} Mount and decrypt')
	println('  ${"stop <name>":-22} Sync state & wipe RAM')
	println('  ${"coldstart <nm> <pt>":-22} RAM-only execution (No Enc)')
	println('  ${"coldstop <name>":-22} Wipe RAM (No Save)')
	println('  ${"resize <nm> <sz>":-22} Resize (+100, -50)')
	println('  ${"list":-22} Show status')
	println('  ${"wipe <name>":-22} Destroy container')
	println('  ${"purge":-22} Reset all')
	println('')
}
