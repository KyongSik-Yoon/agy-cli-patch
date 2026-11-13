use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::symlink;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

// --- POSIX / OS FFI (외부 크레이트 의존성 0, Linux & macOS 호환) ---
const PROT_READ: i32 = 1;
const MAP_PRIVATE: i32 = 2;
const MAP_FAILED: *mut u8 = usize::MAX as *mut u8;
const TCSADRAIN: i32 = 1;

#[cfg(target_os = "linux")]
type Tcflag = u32;
#[cfg(target_os = "linux")]
const ICANON: Tcflag = 0o0000002;
#[cfg(target_os = "linux")]
const ECHO: Tcflag = 0o0000010;
#[cfg(target_os = "linux")]
const ISIG: Tcflag = 0o0000001;
#[cfg(target_os = "linux")]
const TIOCGWINSZ: u64 = 0x5413;
#[cfg(target_os = "linux")]
const VMIN_IDX: usize = 6;
#[cfg(target_os = "linux")]
const VTIME_IDX: usize = 5;
#[cfg(target_os = "linux")]
const FICLONE: u64 = 0x40049409;

#[cfg(target_os = "macos")]
type Tcflag = u64;
#[cfg(target_os = "macos")]
const ICANON: Tcflag = 0x00000100;
#[cfg(target_os = "macos")]
const ECHO: Tcflag = 0x00000008;
#[cfg(target_os = "macos")]
const ISIG: Tcflag = 0x00000080;
#[cfg(target_os = "macos")]
const TIOCGWINSZ: u64 = 0x40087468;
#[cfg(target_os = "macos")]
const VMIN_IDX: usize = 16;
#[cfg(target_os = "macos")]
const VTIME_IDX: usize = 17;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; 32],
    c_ispeed: u32,
    c_ospeed: u32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
    c_iflag: u64,
    c_oflag: u64,
    c_cflag: u64,
    c_lflag: u64,
    c_cc: [u8; 20],
    c_ispeed: u64,
    c_ospeed: u64,
}

#[repr(C)]
struct Winsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

unsafe extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> i32;
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    #[link_name = "read"]
    fn sys_read(fd: i32, buf: *mut u8, count: usize) -> isize;
    fn tcgetattr(fd: i32, termios_p: *mut Termios) -> i32;
    fn tcsetattr(fd: i32, optional_actions: i32, termios_p: *const Termios) -> i32;
    fn isatty(fd: i32) -> i32;
}

struct MmapFile {
    ptr: *mut u8,
    len: usize,
}

impl MmapFile {
    fn open(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("파일 열기 실패 ({}): {e}", path.display()))?;
        let len = file
            .metadata()
            .map_err(|e| format!("메타데이터 조회 실패: {e}"))?
            .len() as usize;
        if len < 64 {
            return Err("파일 크기가 너무 작습니다.".into());
        }
        let ptr = unsafe { mmap(std::ptr::null_mut(), len, PROT_READ, MAP_PRIVATE, file.as_raw_fd(), 0) };
        if ptr == MAP_FAILED {
            return Err("mmap 실패".into());
        }
        Ok(Self { ptr, len })
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for MmapFile {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.ptr != MAP_FAILED {
            unsafe {
                munmap(self.ptr, self.len);
            }
        }
    }
}

// --- 바이너리 포맷 (ELF64 & Mach-O 64) 및 아키텍처 (x86_64 & ARM64) 파서 ---

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Arch {
    X86_64,
    Arm64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Format {
    Elf64,
    MachO64,
}

#[inline]
fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
}

#[inline]
fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

#[inline]
fn read_i32(data: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

#[inline]
fn read_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

struct BinaryContext<'a> {
    data: &'a [u8],
    format: Format,
    arch: Arch,
    funcs: HashMap<&'a str, (usize, usize)>,
}

impl<'a> BinaryContext<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, String> {
        let (format, arch, text_va, text_off) = if &data[..4] == b"\x7fELF" {
            let e_machine = read_u16(data, 0x12);
            let arch = match e_machine {
                0x3e => Arch::X86_64,
                0xb7 => Arch::Arm64,
                other => return Err(format!("지원하지 않는 ELF 아키텍처입니다 (e_machine=0x{other:x}).")),
            };

            let e_shoff = read_u64(data, 0x28) as usize;
            let e_shentsize = read_u16(data, 0x3a) as usize;
            let e_shnum = read_u16(data, 0x3c) as usize;
            let e_shstrndx = read_u16(data, 0x3e) as usize;

            let shdr = |idx: usize| -> (u32, u64, u64, u64) {
                let base = e_shoff + idx * e_shentsize;
                (
                    read_u32(data, base),
                    read_u64(data, base + 16),
                    read_u64(data, base + 24),
                    read_u64(data, base + 32),
                )
            };

            let (_, _, shstr_off, shstr_size) = shdr(e_shstrndx);
            let shstr = &data[shstr_off as usize..(shstr_off + shstr_size) as usize];

            let mut t_va = 0usize;
            let mut t_off = 0usize;
            for i in 0..e_shnum {
                let (sh_name, sh_addr, sh_off, _) = shdr(i);
                let s = &shstr[sh_name as usize..];
                let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
                if &s[..end] == b".text" {
                    t_va = sh_addr as usize;
                    t_off = sh_off as usize;
                    break;
                }
            }
            if t_off == 0 {
                return Err("ELF .text 섹션을 찾을 수 없습니다.".into());
            }
            (Format::Elf64, arch, t_va, t_off)
        } else if read_u32(data, 0) == 0xfeedfacf {
            let cputype = read_u32(data, 4);
            let arch = match cputype {
                0x01000007 => Arch::X86_64,
                0x0100000c => Arch::Arm64,
                other => return Err(format!("지원하지 않는 Mach-O CPU 타입입니다 (0x{other:x}).")),
            };

            let ncmds = read_u32(data, 16) as usize;
            let mut off = 32usize;
            let mut t_va = 0usize;
            let mut t_off = 0usize;
            for _ in 0..ncmds {
                let cmd = read_u32(data, off);
                let cmdsize = read_u32(data, off + 4) as usize;
                if cmd == 0x19 {
                    // LC_SEGMENT_64
                    let nsects = read_u32(data, off + 64) as usize;
                    let mut sect_off = off + 72;
                    for _ in 0..nsects {
                        let sectname = &data[sect_off..sect_off + 16];
                        let end = sectname.iter().position(|&b| b == 0).unwrap_or(16);
                        if &sectname[..end] == b"__text" {
                            t_va = read_u64(data, sect_off + 32) as usize;
                            t_off = read_u32(data, sect_off + 48) as usize;
                            break;
                        }
                        sect_off += 80;
                    }
                }
                off += cmdsize;
            }
            if t_off == 0 {
                return Err("Mach-O __text 섹션을 찾을 수 없습니다.".into());
            }
            (Format::MachO64, arch, t_va, t_off)
        } else {
            return Err("지원하지 않는 바이너리 포맷입니다 (ELF64 또는 Mach-O 64 필요).".into());
        };

        let pcln_magic: &[u8] = match arch {
            Arch::X86_64 => b"\xf1\xff\xff\xff\x00\x00\x01\x08",
            Arch::Arm64 => b"\xf1\xff\xff\xff\x00\x00\x04\x08",
        };
        let pcln_off = find_subslice(data, pcln_magic)
            .ok_or_else(|| "Go .gopclntab 헤더를 찾을 수 없습니다.".to_string())?;

        let nfunc = read_u64(data, pcln_off + 8) as usize;
        let text_start = read_u64(data, pcln_off + 24) as usize;
        let funcname_off = read_u64(data, pcln_off + 32) as usize;
        let ftab_off = read_u64(data, pcln_off + 64) as usize;

        let go_text_off = if text_start != 0 {
            text_off + (text_start - text_va)
        } else if format == Format::Elf64 && arch == Arch::X86_64 {
            // Linux ELF64 CGO/PIE: .text 앞쪽 glibc CRT 패딩(0xcc) 직후 첫 Go 함수 프롤로그 탐색
            let window = &data[text_off..text_off + 0x1000];
            let mut found = None;
            let mut i = 0;
            while i + 12 < window.len() {
                if window[i] == 0xcc {
                    while i < window.len() && window[i] == 0xcc {
                        i += 1;
                    }
                    if i + 9 < window.len()
                        && (window[i] == 0x4c || window[i] == 0x49)
                        && (window[i + 1] == 0x8d || window[i + 1] == 0x3b)
                    {
                        found = Some(text_off + i);
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            found.unwrap_or(text_off)
        } else {
            text_off
        };

        let ftab_base = pcln_off + ftab_off;
        let funcname_base = pcln_off + funcname_off;

        let target_suffixes = [
            "store.cutAtRuneBoundary",
            "render.renderPlannerBody",
            "render.glamourStyleForScheme",
            "parser.ScanDelimiter",
            "extension.(*strikethroughParser).Parse",
            "render.BuildHeader",
            "render.BannerWithInfo",
            "runtime.concatstring3",
        ];

        let mut funcs = HashMap::with_capacity(target_suffixes.len());
        for i in 0..nfunc {
            let entry_off = read_u32(data, ftab_base + i * 8) as usize;
            let func_off = read_u32(data, ftab_base + i * 8 + 4) as usize;
            let name_off = read_i32(data, ftab_base + func_off + 4) as usize;
            let name_start = funcname_base + name_off;
            let s = &data[name_start..];
            let len = s.iter().position(|&b| b == 0).unwrap_or(0);
            if let Ok(full_name) = std::str::from_utf8(&s[..len]) {
                for &target in &target_suffixes {
                    if full_name.ends_with(target) && {
                        let prefix_len = full_name.len() - target.len();
                        prefix_len == 0 || full_name.as_bytes()[prefix_len - 1] == b'/'
                    } {
                        let next_entry_off = read_u32(data, ftab_base + (i + 1) * 8) as usize;
                        funcs.insert(target, (go_text_off + entry_off, go_text_off + next_entry_off));
                        break;
                    }
                }
                if funcs.len() == target_suffixes.len() {
                    break;
                }
            }
        }

        Ok(Self {
            data,
            format,
            arch,
            funcs,
        })
    }

    fn get_func(&self, name: &str) -> Result<(usize, usize), String> {
        self.funcs
            .get(name)
            .copied()
            .ok_or_else(|| format!("심볼 테이블에서 함수를 찾을 수 없습니다: {name}"))
    }
}

// --- 패치 명세 및 아키텍처별(x86_64 / ARM64) 리졸버 ---

struct ByteEdit {
    offset: usize,
    payload: Vec<u8>,
}

struct PatchSpec {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    symbol: &'static str,
    default_on: bool,
    resolver: fn(&BinaryContext) -> Result<Vec<ByteEdit>, String>,
}

const X86_CUT_ORIG: &[u8] = &[0x55, 0x48, 0x89, 0xe5];
const X86_CUT_NEW: &[u8] = &[0x48, 0x89, 0xd8, 0xc3];

const ARM64_CUT_ORIG: &[u8] = &[0x90, 0x0b, 0x40, 0xf9, 0xff, 0x63, 0x30, 0xeb];
const ARM64_CUT_NEW: &[u8] = &[0xe0, 0x03, 0x01, 0xaa, 0xc0, 0x03, 0x5f, 0xd6]; // mov x0, x1; ret

fn is_unpatched_cut(ctx: &BinaryContext) -> Result<bool, String> {
    let (start, _) = ctx.get_func("store.cutAtRuneBoundary")?;
    Ok(match ctx.arch {
        Arch::X86_64 => &ctx.data[start..start + 4] == X86_CUT_ORIG,
        Arch::Arm64 => &ctx.data[start..start + 8] == ARM64_CUT_ORIG,
    })
}

fn resolve_nodrip(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    let (start, _) = ctx.get_func("store.cutAtRuneBoundary")?;
    match ctx.arch {
        Arch::X86_64 => {
            let cur = &ctx.data[start..start + 4];
            if cur != X86_CUT_ORIG && cur != X86_CUT_NEW {
                return Err(format!("cutAtRuneBoundary x86_64 프롤로그 불일치 (@0x{start:x})"));
            }
            Ok(vec![ByteEdit {
                offset: start,
                payload: X86_CUT_NEW.to_vec(),
            }])
        }
        Arch::Arm64 => {
            let cur = &ctx.data[start..start + 8];
            if cur != ARM64_CUT_ORIG && cur != ARM64_CUT_NEW {
                return Err(format!("cutAtRuneBoundary ARM64 프롤로그 불일치 (@0x{start:x})"));
            }
            Ok(vec![ByteEdit {
                offset: start,
                payload: ARM64_CUT_NEW.to_vec(),
            }])
        }
    }
}

fn resolve_batch(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    let (start, end) = ctx.get_func("render.renderPlannerBody")?;
    let body = &ctx.data[start..end];
    let mut edits = Vec::new();

    match ctx.arch {
        Arch::X86_64 => {
            for i in 0..body.len().saturating_sub(21) {
                if body[i] == 0x83
                    && (0xf8..=0xff).contains(&body[i + 1])
                    && body[i + 2] == 0x01
                    && body[i + 3] == 0x76
                    && body[i + 4] == 0x0e
                    && body[i + 5] == 0x83
                    && (0xf8..=0xff).contains(&body[i + 6])
                    && body[i + 7] == 0x08
                    && body[i + 8] == 0x74
                    && body[i + 9] == 0x09
                    && body[i + 10] == 0x83
                    && (0xf8..=0xff).contains(&body[i + 11])
                    && body[i + 12] == 0x0b
                    && body[i + 13] == 0x0f
                    && body[i + 14] == 0x85
                {
                    edits.push(ByteEdit {
                        offset: start + i + 19,
                        payload: vec![0x31, 0xc0, 0x31, 0xdb, 0x31, 0xc9, 0xc9, 0xc3],
                    });
                }
            }
        }
        Arch::Arm64 => {
            for off in (0..body.len().saturating_sub(28)).step_by(4) {
                let i0 = read_u32(body, off);
                let i1 = read_u32(body, off + 4);
                let i2 = read_u32(body, off + 8);
                let i3 = read_u32(body, off + 12);
                let i4 = read_u32(body, off + 16);
                let i5 = read_u32(body, off + 20);
                if (i0 & 0xffff_fc1f) == 0x7100_041f
                    && i1 == 0x5400_00a9
                    && (i2 & 0xffff_fc1f) == 0x7100_201f
                    && i3 == 0x5400_0060
                    && (i4 & 0xffff_fc1f) == 0x7100_2c1f
                    && (i5 & 0xff00_001f) == 0x5400_0001
                {
                    let mut imm19 = ((i5 >> 5) & 0x7ffff) as i32;
                    if (imm19 & 0x40000) != 0 {
                        imm19 -= 0x80000;
                    }
                    // mov x0, xzr (0xaa1f03e0); mov x1, xzr (0xaa1f03e1); b <done_epilogue>
                    let b_insn = 0x1400_0000u32 | (((imm19 - 3) as u32) & 0x03ff_ffff);
                    let mut payload = Vec::with_capacity(12);
                    payload.extend_from_slice(&0xaa1f_03e0u32.to_le_bytes());
                    payload.extend_from_slice(&0xaa1f_03e1u32.to_le_bytes());
                    payload.extend_from_slice(&b_insn.to_le_bytes());
                    edits.push(ByteEdit {
                        offset: start + off + 24,
                        payload,
                    });
                }
            }
        }
    }

    if edits.len() != 1 {
        return Err(format!(
            "renderPlannerBody 분기 패턴 매칭 실패 (매칭 수: {})",
            edits.len()
        ));
    }
    Ok(edits)
}

fn resolve_heading(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    let (start, end) = ctx.get_func("render.glamourStyleForScheme")?;
    let body = &ctx.data[start..end];

    match ctx.arch {
        Arch::X86_64 => {
            let mut matches = Vec::new();
            'outer: for i in 0..body.len().saturating_sub(27 * 5) {
                for k in 0..5 {
                    let chunk = &body[i + k * 27..i + (k + 1) * 27];
                    let expected_len = (k + 3) as u8;
                    if &chunk[0..3] != &[0x48, 0x8d, 0x0d]
                        || &chunk[7..11] != &[0x48, 0x89, 0x8c, 0x24]
                        || &chunk[15..19] != &[0x48, 0xc7, 0x84, 0x24]
                        || (chunk[23] != expected_len && chunk[23] != 0)
                        || &chunk[24..27] != &[0x00, 0x00, 0x00]
                    {
                        continue 'outer;
                    }
                }
                matches.push(start + i);
            }
            if matches.len() != 1 {
                return Err(format!(
                    "glamourStyleForScheme x86_64 헤딩 패턴 매칭 실패 (매칭 수: {})",
                    matches.len()
                ));
            }
            let base = matches[0];
            Ok((0..5)
                .map(|k| ByteEdit {
                    offset: base + k * 27 + 23,
                    payload: vec![0x00],
                })
                .collect())
        }
        Arch::Arm64 => {
            // H1..H6 (총 6개)가 sp + base + k*0xd0 (k=0..5) 간격으로 연속 배치됨.
            // 각 항목은 `add x27, sp, #imm12` 직후 `stp x1, xN, [x27]` (또는 패치된 `stp xzr, xzr, [x27]`).
            let mut stp_map = Vec::new();
            for off in (0..body.len().saturating_sub(8)).step_by(4) {
                let i0 = read_u32(body, off);
                let i1 = read_u32(body, off + 4);
                if (i0 & 0xffc0_03ff) == 0x9100_03fb
                    && ((i1 & 0xffe0_83ff) == 0xa900_0361 || i1 == 0xa900_7f7f)
                {
                    let imm12 = (i0 >> 10) & 0xfff;
                    stp_map.push((imm12, start + off + 4));
                }
            }
            let map: HashMap<u32, usize> = stp_map.iter().copied().collect();
            let mut found_h2_to_h6 = None;
            for &(imm, _) in &stp_map {
                if (0..6).all(|k| map.contains_key(&(imm + k * 0xd0))) {
                    found_h2_to_h6 = Some(
                        (1..6)
                            .map(|k| ByteEdit {
                                offset: map[&(imm + k * 0xd0)],
                                payload: 0xa900_7f7fu32.to_le_bytes().to_vec(), // stp xzr, xzr, [x27]
                            })
                            .collect::<Vec<_>>(),
                    );
                    break;
                }
            }
            found_h2_to_h6.ok_or_else(|| "glamourStyleForScheme ARM64 헤딩 패턴 매칭 실패".into())
        }
    }
}

fn resolve_cjk_bold(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    let (start, end) = ctx.get_func("parser.ScanDelimiter")?;
    let body = &ctx.data[start..end];

    match ctx.arch {
        Arch::X86_64 => {
            let mut matches = Vec::new();
            for i in 0..body.len().saturating_sub(54) {
                let w = &body[i..i + 54];
                if w[0] == 0x84
                    && w[1] == 0xc0
                    && (w[2] == 0x74 || w[2] == 0xeb)
                    && w[3] == 0x10
                    && &w[4..8] == &[0x0f, 0xb6, 0x54, 0x24]
                    && &w[9..13] == &[0x84, 0xd2, 0x75, 0x0c]
                    && &w[13..17] == &[0x0f, 0xb6, 0x5c, 0x24]
                    && &w[18..20] == &[0xeb, 0x0a]
                    && &w[25..36]
                        == &[0xbb, 0x01, 0x00, 0x00, 0x00, 0x84, 0xd2, 0x74, 0x0b, 0x89, 0xc1]
                    && &w[41..45] == &[0x31, 0xc0, 0xeb, 0x18]
                    && &w[50..52] == &[0x84, 0xd2]
                    && (w[52] == 0x74 || w[52] == 0xeb)
                    && w[53] == 0x08
                {
                    matches.push(start + i);
                }
            }
            if matches.len() != 1 {
                return Err(format!(
                    "ScanDelimiter x86_64 플랭킹 패턴 매칭 실패 (매칭 수: {})",
                    matches.len()
                ));
            }
            let base = matches[0];
            Ok(vec![
                ByteEdit {
                    offset: base + 2,
                    payload: vec![0xeb],
                },
                ByteEdit {
                    offset: base + 52,
                    payload: vec![0xeb],
                },
            ])
        }
        Arch::Arm64 => {
            let mut matches = Vec::new();
            for off in (0..body.len().saturating_sub(60)).step_by(4) {
                let i0 = read_u32(body, off);
                let i4 = read_u32(body, off + 16);
                let i6 = read_u32(body, off + 24);
                let i13 = read_u32(body, off + 52);
                if (i0 == 0x3600_00a0 || i0 == 0x1400_0005)
                    && i4 == 0x1400_0003
                    && i6 == 0xb240_03e3
                    && (i13 == 0x3600_0082 || i13 == 0x1400_0004)
                {
                    matches.push(start + off);
                }
            }
            if matches.len() != 1 {
                return Err(format!(
                    "ScanDelimiter ARM64 플랭킹 패턴 매칭 실패 (매칭 수: {})",
                    matches.len()
                ));
            }
            let base = matches[0];
            Ok(vec![
                ByteEdit {
                    offset: base,
                    payload: 0x1400_0005u32.to_le_bytes().to_vec(), // b +0x14
                },
                ByteEdit {
                    offset: base + 52,
                    payload: 0x1400_0004u32.to_le_bytes().to_vec(), // b +0x10
                },
            ])
        }
    }
}

fn resolve_tilde_strike(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    let (start, end) = ctx.get_func("extension.(*strikethroughParser).Parse")?;
    let body = &ctx.data[start..end];

    match ctx.arch {
        Arch::X86_64 => {
            let mut matches = Vec::new();
            for i in 0..body.len().saturating_sub(21) {
                let w = &body[i..i + 21];
                if &w[0..3] == &[0x8b, 0x7c, 0x24]
                    && w[4] == 0xbe
                    && (w[5] == 0x01 || w[5] == 0x02)
                    && &w[6..9] == &[0x00, 0x00, 0x00]
                    && &w[9..12] == &[0x4c, 0x8d, 0x05]
                    && w[16] == 0xe8
                {
                    matches.push(start + i + 5);
                }
            }
            if matches.len() != 1 {
                return Err(format!(
                    "strikethroughParser.Parse x86_64 패턴 매칭 실패 (매칭 수: {})",
                    matches.len()
                ));
            }
            Ok(vec![ByteEdit {
                offset: matches[0],
                payload: vec![0x02],
            }])
        }
        Arch::Arm64 => {
            let mut matches = Vec::new();
            for off in (0..body.len().saturating_sub(16)).step_by(4) {
                let i0 = read_u32(body, off);
                let i1 = read_u32(body, off + 4);
                let i2 = read_u32(body, off + 8);
                let i3 = read_u32(body, off + 12);
                if (i0 == 0xb240_03e4 || i0 == 0xb27f_03e4 || i0 == 0xd280_0044)
                    && (i1 & 0x9f00_001f) == 0x9000_0005
                    && (i2 & 0xffc0_03ff) == 0x9100_00a5
                    && (i3 >> 26) == 0x25
                {
                    matches.push(start + off);
                }
            }
            if matches.len() != 1 {
                return Err(format!(
                    "strikethroughParser.Parse ARM64 패턴 매칭 실패 (매칭 수: {})",
                    matches.len()
                ));
            }
            Ok(vec![ByteEdit {
                offset: matches[0],
                payload: 0xb27f_03e4u32.to_le_bytes().to_vec(), // orr x4, xzr, #2
            }])
        }
    }
}

// banner / release-notes 패치가 공유하는 0xcc 패딩 공간(cave) 배치.
// 두 패치를 따로 적용해도 겹치지 않도록 고정 오프셋을 쓴다.
const CAVE_MIN: usize = 1024;
const CAVE_CHAN_OFF: usize = 0; // "patch v{ver}" (≤ 32바이트)
const CAVE_NOTES_OFF: usize = 64; // 릴리즈 노트 문자열 + 트램펄린

fn find_cave(ctx: &BinaryContext) -> Result<usize, String> {
    let needle = [0xccu8; CAVE_MIN];
    ctx.data
        .windows(needle.len())
        .position(|w| w == needle)
        .ok_or_else(|| format!("실행 파일 내 0xcc 여유 공간({CAVE_MIN}바이트)을 찾을 수 없습니다."))
}

fn resolve_banner(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    match ctx.arch {
        Arch::X86_64 => {
            let (bwi_start, bwi_end) = ctx.get_func("render.BannerWithInfo")?;
            let cave_offset = find_cave(ctx)?;

            // 제품명 옆 괄호 안에 표시: "Antigravity CLI 1.5.7 (patch v0.2.0)"
            let chan = format!("patch v{}", env!("CARGO_PKG_VERSION")).into_bytes();
            assert!(chan.len() <= CAVE_NOTES_OFF - CAVE_CHAN_OFF);
            let chan_va = cave_offset + CAVE_CHAN_OFF;

            let mut edits = vec![ByteEdit {
                offset: chan_va,
                payload: chan.clone(),
            }];

            // BannerWithInfo 패치: 빈 채널 대신 주입된 채널 문자열 포맷 루틴 활성화
            let bwi_body = &ctx.data[bwi_start..bwi_end];
            let mut bwi_matches = Vec::new();
            for i in 0..bwi_body.len().saturating_sub(55) {
                if &bwi_body[i..i + 5] == &[0x48, 0x85, 0xd2, 0x0f, 0x84]
                    && &bwi_body[i + 9..i + 17] == &[0x48, 0x89, 0x9c, 0x24, 0xb0, 0x02, 0x00, 0x00]
                    && &bwi_body[i + 17..i + 21] == &[0x48, 0x89, 0x84, 0x24]
                {
                    bwi_matches.push(bwi_start + i);
                }
            }
            if bwi_matches.len() != 1 {
                return Err(format!(
                    "BannerWithInfo 채널 검사 패턴 매칭 실패 (매칭 수: {})",
                    bwi_matches.len()
                ));
            }
            let chan_site = bwi_matches[0];
            let chan_site_end = chan_site + 55;

            // 원본은 채널 분기 진입 시 제품명 문자열(rax=ptr, rbx=len)을 스택 슬롯에 저장하고,
            // Sprintf 이후 그 슬롯을 다시 읽어 concatstring2 로 이어 붙인다.
            // 이 두 저장(mov %rbx,0x2b0(%rsp) / mov %rax,0x320(%rsp))을 건너뛰면
            // 초기화되지 않은 슬롯을 이어 붙이다 SIGSEGV 가 나므로 그대로 보존한다.
            let mut chan_patch = ctx.data[chan_site + 9..chan_site + 25].to_vec();
            let pc = chan_site + chan_patch.len() + 7;
            let disp_chan = (chan_va as i64) - (pc as i64);
            chan_patch.extend_from_slice(&[0x48, 0x8d, 0x0d]);
            chan_patch.extend_from_slice(&(disp_chan as i32).to_le_bytes());

            chan_patch.push(0xba);
            chan_patch.extend_from_slice(&(chan.len() as u32).to_le_bytes());

            let pc = chan_site + chan_patch.len() + 5;
            let rel_skip = (chan_site_end as i64) - (pc as i64);
            chan_patch.push(0xe9);
            chan_patch.extend_from_slice(&(rel_skip as i32).to_le_bytes());

            while chan_patch.len() < 55 {
                chan_patch.push(0x90);
            }

            edits.push(ByteEdit {
                offset: chan_site,
                payload: chan_patch,
            });
            Ok(edits)
        }
        Arch::Arm64 => Err("banner 패치는 현재 x86_64 환경에서 우선 지원됩니다.".into()),
    }
}

/// 릴리즈 노트 본문. `release-notes` 패치(배너 주입)와 `--notes` 출력이 같은 문구를 쓴다.
fn release_notes_text() -> String {
    const ITEMS: &[(&str, &str)] = &[
        ("nodrip", "instant streaming (16ms typewriter drip removed)"),
        ("batch", "full answer rendered at once on completion"),
        ("heading", "'##' prefixes hidden on H2-H6"),
        ("cjk-bold", "**bold** kept before Korean particles"),
        ("tilde-strike", "only '~~' strikes through, single '~' stays"),
        ("banner", "patch version shown next to the product name"),
    ];
    let mut out = format!(
        " \x1b[1mWhat's new in agy-cli-patch v{}:\x1b[0m",
        env!("CARGO_PKG_VERSION")
    );
    for (id, desc) in ITEMS {
        out.push_str(&format!("\n \x1b[32m•\x1b[0m \x1b[1m{id}\x1b[0m: {desc}"));
    }
    out.push_str("\n \x1b[90mGitHub: https://github.com/KyongSik-Yoon/agy-cli-patch\x1b[0m");
    out.push_str("\n \x1b[90mAccount: KyongSik-Yoon <sam1287@gmail.com>\x1b[0m");
    out
}

fn resolve_release_notes(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    match ctx.arch {
        Arch::X86_64 => {
            let (bh_start, bh_end) = ctx.get_func("render.BuildHeader")?;
            let (concat3_start, _) = ctx.get_func("runtime.concatstring3")?;
            let cave_offset = find_cave(ctx)?;

            let notes = format!("\n\n{}", release_notes_text()).into_bytes();

            let notes_va = cave_offset + CAVE_NOTES_OFF;
            let notes_len = notes.len();
            let tramp_va = (notes_va + notes_len + 15) & !15;

            // 트램펄린 루틴 생성:
            // lea notes(%rip), %r8
            // mov $notes_len, %r9d
            // jmp concatstring3   (tail call)
            //
            // call 이 아니라 jmp 여야 한다. call 로 들어가면 concatstring3 의 리턴 주소가
            // pclntab 에 없는 동굴(cave)을 가리켜 GC/스택 확장 시 Go 언와인더가 실패하고,
            // morestack 경로의 레지스터 인자 스필(SP+8~)이 트램펄린의 리턴 주소를 덮어쓴다.
            // tail jmp 면 BuildHeader 가 concatstring3 를 직접 호출한 것과 동일한 프레임이 된다
            // (BuildHeader 의 outgoing 인자 영역은 7워드 스필을 충분히 수용함).
            let mut tramp = Vec::new();
            let pc = tramp_va + 7;
            let disp = (notes_va as i64) - (pc as i64);
            tramp.extend_from_slice(&[0x4c, 0x8d, 0x05]);
            tramp.extend_from_slice(&(disp as i32).to_le_bytes());

            tramp.extend_from_slice(&[0x41, 0xb9]);
            tramp.extend_from_slice(&(notes_len as u32).to_le_bytes());

            let pc = tramp_va + tramp.len() + 5;
            let rel_c3 = (concat3_start as i64) - (pc as i64);
            tramp.push(0xe9);
            tramp.extend_from_slice(&(rel_c3 as i32).to_le_bytes());

            if tramp_va + tramp.len() > cave_offset + CAVE_MIN {
                return Err("릴리즈 노트가 0xcc 여유 공간을 초과합니다.".into());
            }

            let mut edits = vec![
                ByteEdit {
                    offset: notes_va,
                    payload: notes,
                },
                ByteEdit {
                    offset: tramp_va,
                    payload: tramp,
                },
            ];

            // BuildHeader 패치: concatstring2 호출을 트램펄린(concatstring3) 호출로 변경
            let bh_body = &ctx.data[bh_start..bh_end];
            let bh_pat = [0x48, 0x89, 0xc7, 0x48, 0x89, 0xde, 0x31, 0xc0, 0x48, 0x8d, 0x1d];
            let bh_matches: Vec<_> = bh_body
                .windows(bh_pat.len())
                .enumerate()
                .filter(|(_, w)| *w == bh_pat)
                .map(|(i, _)| bh_start + i)
                .collect();

            if bh_matches.len() != 1 {
                return Err(format!(
                    "BuildHeader concatstring2 패턴 매칭 실패 (매칭 수: {})",
                    bh_matches.len()
                ));
            }
            let call_site = bh_matches[0] + 17;
            if ctx.data[call_site] != 0xe8 {
                return Err(format!(
                    "BuildHeader call site op 불일치 (기대: 0xe8, 실제: 0x{:02x})",
                    ctx.data[call_site]
                ));
            }

            let pc = call_site + 5;
            let rel_tramp = (tramp_va as i64) - (pc as i64);
            let mut call_bytes = vec![0xe8];
            call_bytes.extend_from_slice(&(rel_tramp as i32).to_le_bytes());
            edits.push(ByteEdit {
                offset: call_site,
                payload: call_bytes,
            });

            Ok(edits)
        }
        Arch::Arm64 => Err("release-notes 패치는 현재 x86_64 환경에서 우선 지원됩니다.".into()),
    }
}

const PATCH_REGISTRY: &[PatchSpec] = &[
    PatchSpec {
        id: "nodrip",
        title: "타자기 딜레이 제거 (No Drip)",
        description: "16ms마다 12바이트씩 끊어 찍는 타자기 효과를 끄고 수신 즉시 반영",
        symbol: "store.cutAtRuneBoundary",
        default_on: true,
        resolver: resolve_nodrip,
    },
    PatchSpec {
        id: "batch",
        title: "응답 완료 시 한 번에 일괄 출력 (Batch Render)",
        description: "생성 중에는 본문을 숨겼다가 답변이 완료(DONE)되면 전체를 한 번에 출력",
        symbol: "render.renderPlannerBody",
        default_on: true,
        resolver: resolve_batch,
    },
    PatchSpec {
        id: "heading",
        title: "마크다운 헤딩 '##' 기호 숨김 (Clean Headings)",
        description: "H2~H6 제목 앞에 붙는 '## '~'###### ' 프리픽스를 제거하고 스타일만 유지",
        symbol: "render.glamourStyleForScheme",
        default_on: true,
        resolver: resolve_heading,
    },
    PatchSpec {
        id: "cjk-bold",
        title: "구두점 뒤 한글 조사 볼드(**) 깨짐 수정 (CJK Bold Fix)",
        description: "**\"문구\"**라는, **용어(`code`)**는 처럼 뒤에 한글 조사가 붙어도 볼드 유지",
        symbol: "goldmark/parser.ScanDelimiter",
        default_on: true,
        resolver: resolve_cjk_bold,
    },
    PatchSpec {
        id: "tilde-strike",
        title: "단일 물결표(~) 취소선 오작동 방지 (Double-Tilde Strikethrough)",
        description: "1.5.0~1.5.6 같은 범위 표기용 단일 '~'에 취소선이 그어지지 않도록 '~~'만 허용",
        symbol: "goldmark/extension.(*strikethroughParser).Parse",
        default_on: true,
        resolver: resolve_tilde_strike,
    },
    PatchSpec {
        id: "banner",
        title: "제품명 옆 패치 버전 표시 (Patch Version Tag)",
        description: "상단 'Antigravity CLI 1.5.7' 옆에 '(patch v0.2.0)' 형태로 패치 버전 표시",
        symbol: "render.BannerWithInfo",
        default_on: true,
        resolver: resolve_banner,
    },
    PatchSpec {
        id: "release-notes",
        title: "상단 배너 릴리즈 노트 표시 (Release Notes)",
        description: "로고 아래에 패치 기능 요약 및 GitHub 정보 표시 (기본 꺼짐, -p 로 명시해야 적용)",
        symbol: "render.BuildHeader",
        default_on: false,
        resolver: resolve_release_notes,
    },
];

// --- 파일 복사 및 macOS 코드 서명(codesign) ---

fn copy_reflink(src: &Path, dst: &Path) -> Result<(), String> {
    if dst.exists() || dst.is_symlink() {
        let _ = fs::remove_file(dst);
    }
    #[cfg(target_os = "linux")]
    if let (Ok(s_file), Ok(d_file)) = (
        File::open(src),
        OpenOptions::new().write(true).create(true).truncate(true).open(dst),
    ) {
        let ret = unsafe { ioctl(d_file.as_raw_fd(), FICLONE, s_file.as_raw_fd()) };
        if ret == 0 {
            if let Ok(meta) = fs::metadata(src) {
                let _ = fs::set_permissions(dst, meta.permissions());
            }
            return Ok(());
        }
    }
    fs::copy(src, dst)
        .map(|_| ())
        .map_err(|e| format!("파일 복사 실패 ({} -> {}): {e}", src.display(), dst.display()))
}

fn resign_if_macho(dst: &Path, format: Format) {
    if format != Format::MachO64 {
        return;
    }
    if which_in_path("codesign").is_some() {
        match Command::new("codesign")
            .args(["-f", "-s", "-"])
            .arg(dst)
            .output()
        {
            Ok(out) if out.status.success() => {
                println!("[+] macOS ad-hoc 코드 서명 갱신 완료 (codesign -f -s -)");
            }
            Ok(out) => {
                eprintln!(
                    "[!] 경고: codesign 실패: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            Err(_) => {}
        }
    }
}

// --- 바이너리 자동 탐색 ---

fn is_supported_binary(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else { return false };
    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }
    &magic == b"\x7fELF" || u32::from_le_bytes(magic) == 0xfeedfacf
}

fn which_in_path(cmd: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        let full = dir.join(cmd);
        if full.is_file() {
            return Some(full);
        }
    }
    None
}

fn binary_version(path: &Path) -> String {
    Command::new(path)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "확인 불가".to_string())
}

fn detect_default_binary() -> PathBuf {
    let home = env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    let mut candidates = Vec::new();

    if let Some(env_bin) = env::var_os("AGY_BIN") {
        candidates.push(PathBuf::from(env_bin));
    }

    candidates.push(home.join(".local/share/mise/installs/agy/latest/antigravity"));

    if which_in_path("mise").is_some() {
        for name in ["antigravity", "agy"] {
            if let Ok(out) = Command::new("mise").args(["which", name]).output() {
                if out.status.success() {
                    if let Ok(s) = String::from_utf8(out.stdout) {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            candidates.push(PathBuf::from(trimmed));
                        }
                    }
                }
            }
        }
    }

    for name in ["antigravity", "agy"] {
        if let Some(p) = which_in_path(name) {
            if let Ok(canon) = fs::canonicalize(&p) {
                if let Some(parent) = canon.parent() {
                    let sib = parent.join("antigravity");
                    if sib != canon && sib.exists() {
                        candidates.push(sib);
                    }
                }
                candidates.push(canon);
            }
        }
    }

    candidates.extend([
        home.join(".local/bin/antigravity"),
        home.join(".antigravity/bin/antigravity"),
        PathBuf::from("/opt/homebrew/bin/antigravity"),
        PathBuf::from("/usr/local/bin/antigravity"),
        PathBuf::from("/usr/bin/antigravity"),
    ]);

    for cand in candidates {
        let resolved = fs::canonicalize(&cand).unwrap_or(cand);
        if is_supported_binary(&resolved) {
            return resolved;
        }
    }

    home.join(".local/share/mise/installs/agy/latest/antigravity")
}

// --- 인터랙티브 터미널 UI (외부 크레이트 없이 ANSI 이스케이프로 직접 그림) ---

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Key {
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    Enter,
    Esc,
    Backspace,
    Delete,
    CtrlC,
    Char(char),
}

/// 한 번의 read 로 들어온 바이트를 키 목록으로 해석한다 (붙여넣기·빠른 입력 시 여러 키가 함께 온다).
fn parse_keys(buf: &[u8]) -> Vec<Key> {
    let mut keys = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let b = buf[i];
        match b {
            0x1b => {
                let rest = &buf[i + 1..];
                if rest.len() >= 2 && (rest[0] == b'[' || rest[0] == b'O') {
                    // CSI/SS3: 파라미터 바이트(0x30–0x3f) 다음에 종결 바이트가 온다
                    let mut j = 1;
                    while j < rest.len() && (0x30..=0x3f).contains(&rest[j]) {
                        j += 1;
                    }
                    if j < rest.len() {
                        let params = &rest[1..j];
                        let key = match (rest[j], params) {
                            (b'A', _) => Some(Key::Up),
                            (b'B', _) => Some(Key::Down),
                            (b'C', _) => Some(Key::Right),
                            (b'D', _) => Some(Key::Left),
                            (b'H', _) => Some(Key::Home),
                            (b'F', _) => Some(Key::End),
                            (b'~', b"1") | (b'~', b"7") => Some(Key::Home),
                            (b'~', b"4") | (b'~', b"8") => Some(Key::End),
                            (b'~', b"3") => Some(Key::Delete),
                            _ => None,
                        };
                        keys.extend(key);
                        i += 1 + j + 1;
                    } else {
                        i = buf.len();
                    }
                } else {
                    keys.push(Key::Esc);
                    i += 1;
                }
            }
            b'\r' | b'\n' => {
                keys.push(Key::Enter);
                i += 1;
            }
            0x7f | 0x08 => {
                keys.push(Key::Backspace);
                i += 1;
            }
            0x03 => {
                keys.push(Key::CtrlC);
                i += 1;
            }
            0x00..=0x1f => i += 1,
            _ => {
                let len = match b {
                    0xc0..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf7 => 4,
                    _ => 1,
                };
                let end = (i + len).min(buf.len());
                if let Some(c) = std::str::from_utf8(&buf[i..end]).ok().and_then(|s| s.chars().next()) {
                    keys.push(Key::Char(c));
                }
                i = end;
            }
        }
    }
    keys
}

/// 터미널 표시 폭. 한글·CJK·전각 문자는 2칸으로 계산한다.
fn char_width(c: char) -> usize {
    let cp = c as u32;
    if c.is_control() || matches!(cp, 0x0300..=0x036f | 0x200b..=0x200f | 0xfe00..=0xfe0f) {
        0
    } else if matches!(
        cp,
        0x1100..=0x115f
            | 0x2e80..=0x303e
            | 0x3041..=0x33ff
            | 0x3400..=0x4dbf
            | 0x4e00..=0x9fff
            | 0xa000..=0xa4cf
            | 0xac00..=0xd7a3
            | 0xf900..=0xfaff
            | 0xfe30..=0xfe4f
            | 0xff00..=0xff60
            | 0xffe0..=0xffe6
            | 0x1f300..=0x1f64f
            | 0x1f900..=0x1f9ff
            | 0x20000..=0x3fffd
    ) {
        2
    } else {
        1
    }
}

fn str_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

/// 표시 폭이 max 를 넘으면 뒤를 잘라 '…'을 붙인다.
fn truncate_end(s: &str, max: usize) -> String {
    if str_width(s) <= max {
        return s.to_string();
    }
    let mut out = String::new();
    let mut w = 0;
    for c in s.chars() {
        let cw = char_width(c);
        if w + cw + 1 > max {
            break;
        }
        out.push(c);
        w += cw;
    }
    if max > 0 {
        out.push('…');
    }
    out
}

/// 경로처럼 끝부분이 중요한 문자열은 앞을 잘라 '…'을 붙인다.
fn truncate_start(s: &str, max: usize) -> String {
    if str_width(s) <= max {
        return s.to_string();
    }
    let mut tail: Vec<char> = Vec::new();
    let mut w = 0;
    for c in s.chars().rev() {
        let cw = char_width(c);
        if w + cw + 1 > max {
            break;
        }
        tail.push(c);
        w += cw;
    }
    let mut out = String::from("…");
    out.extend(tail.iter().rev());
    out
}

/// 공백 기준 줄바꿈. 한 단어가 폭보다 길면 글자 단위로 자른다.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut cur = String::new();
    let mut cur_w = 0;
    for word in text.split(' ') {
        let ww = str_width(word);
        let sep = usize::from(!cur.is_empty());
        if cur_w + sep + ww <= width {
            if sep == 1 {
                cur.push(' ');
            }
            cur.push_str(word);
            cur_w += sep + ww;
            continue;
        }
        if !cur.is_empty() {
            lines.push(std::mem::take(&mut cur));
            cur_w = 0;
        }
        for c in word.chars() {
            let cw = char_width(c);
            if cur_w + cw > width {
                lines.push(std::mem::take(&mut cur));
                cur_w = 0;
            }
            cur.push(c);
            cur_w += cw;
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

/// HOME 아래 경로는 '~' 로 줄여 보여준다.
fn tilde_path(p: &Path) -> String {
    if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
        if let Ok(rest) = p.strip_prefix(&home) {
            return format!("~/{}", rest.display());
        }
    }
    p.display().to_string()
}

const S_PLAIN: &str = "";
const S_BOLD: &str = "1";
const S_DIM: &str = "2";
const S_ACCENT: &str = "36";
const S_ACCENT_B: &str = "1;36";
const S_OK: &str = "32";
const S_WARN: &str = "33";
const S_ERR: &str = "31";
const S_CARET: &str = "7";

/// 스타일이 붙은 조각(span)들로 이루어진 한 줄. 그릴 때 화면 폭에 맞춰 자른다.
#[derive(Default)]
struct Line {
    spans: Vec<(&'static str, String)>,
}

impl Line {
    fn new() -> Self {
        Self::default()
    }

    fn s(mut self, style: &'static str, text: impl Into<String>) -> Self {
        self.spans.push((style, text.into()));
        self
    }

    fn width(&self) -> usize {
        self.spans.iter().map(|(_, t)| str_width(t)).sum()
    }

    /// 왼쪽 내용과 오른쪽 내용을 양 끝에 정렬한다. 폭이 모자라면 오른쪽을 생략한다.
    fn with_right(mut self, right: Line, width: usize) -> Self {
        let (lw, rw) = (self.width(), right.width());
        if lw + rw + 2 <= width {
            self.spans.push((S_PLAIN, " ".repeat(width - lw - rw)));
            self.spans.extend(right.spans);
        }
        self
    }

    fn render(&self, width: usize, color: bool) -> String {
        let mut out = String::new();
        let mut used = 0;
        for (style, text) in &self.spans {
            let remain = width.saturating_sub(used);
            if remain == 0 {
                break;
            }
            let t = truncate_end(text, remain);
            used += str_width(&t);
            if color && !style.is_empty() {
                out.push_str("\x1b[");
                out.push_str(style);
                out.push('m');
                out.push_str(&t);
                out.push_str("\x1b[0m");
            } else {
                out.push_str(&t);
            }
        }
        out
    }
}

fn rule(width: usize) -> Line {
    Line::new().s(S_DIM, format!(" {}", "─".repeat(width.saturating_sub(2))))
}

fn key_hints(hints: &[(&str, &str)]) -> Line {
    let mut line = Line::new().s(S_PLAIN, " ");
    for (i, (k, label)) in hints.iter().enumerate() {
        if i > 0 {
            line = line.s(S_PLAIN, "   ");
        }
        line = line.s(S_BOLD, *k).s(S_DIM, format!(" {label}"));
    }
    line
}

/// raw 모드 + 대체 화면 버퍼. Drop 시(패닉 포함) 터미널을 원래대로 되돌린다.
struct Tui {
    orig: Termios,
}

impl Tui {
    fn enter() -> Result<Self, String> {
        let mut orig = unsafe { std::mem::zeroed::<Termios>() };
        if unsafe { tcgetattr(0, &mut orig) } != 0 {
            return Err("터미널 설정을 읽을 수 없습니다.".into());
        }
        let mut raw = orig;
        // ISIG 도 끈다: Ctrl+C 를 키로 받아 화면을 복구한 뒤 종료하기 위함
        raw.c_lflag &= !(ICANON | ECHO | ISIG);
        // VMIN=0, VTIME=2: 입력이 없어도 0.2초마다 깨어나 터미널 크기 변경을 반영
        raw.c_cc[VMIN_IDX] = 0;
        raw.c_cc[VTIME_IDX] = 2;
        if unsafe { tcsetattr(0, TCSADRAIN, &raw) } != 0 {
            return Err("터미널을 raw 모드로 전환할 수 없습니다.".into());
        }
        let tui = Tui { orig };
        tui.write("\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J");
        Ok(tui)
    }

    fn write(&self, s: &str) {
        let mut out = io::stdout().lock();
        let _ = out.write_all(s.as_bytes());
        let _ = out.flush();
    }

    fn size() -> (usize, usize) {
        let mut ws = Winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        for fd in [1, 0] {
            if unsafe { ioctl(fd, TIOCGWINSZ, &mut ws as *mut Winsize) } == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
                return (ws.ws_col as usize, ws.ws_row as usize);
            }
        }
        (80, 24)
    }

    /// 화면 전체를 지우지 않고 줄마다 덮어쓴 뒤 남는 부분만 지워 깜빡임을 없앤다.
    fn draw(&self, lines: &[String]) {
        let mut buf = String::from("\x1b[H");
        for (i, l) in lines.iter().enumerate() {
            if i > 0 {
                buf.push_str("\r\n");
            }
            buf.push_str(l);
            buf.push_str("\x1b[0m\x1b[K");
        }
        buf.push_str("\x1b[J");
        self.write(&buf);
    }

    fn read_keys(&self) -> Vec<Key> {
        let mut buf = [0u8; 64];
        let n = unsafe { sys_read(0, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            return Vec::new();
        }
        parse_keys(&buf[..n as usize])
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        self.write("\x1b[0m\x1b[?25h\x1b[?1049l");
        unsafe { tcsetattr(0, TCSADRAIN, &self.orig) };
    }
}

/// 출력 이름(파일명 또는 경로)을 실제 생성 경로와 ~/.local/bin 링크 이름으로 바꾼다.
fn output_paths(bin_dir: &Path, out_name: &str) -> (PathBuf, String) {
    if out_name.contains('/') {
        let p = PathBuf::from(out_name);
        let name = p
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("agy-patched")
            .to_string();
        (p, name)
    } else {
        (bin_dir.join(out_name), out_name.to_string())
    }
}

fn local_bin_link(name: &str) -> Option<PathBuf> {
    env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/bin").join(name))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Patches,
    Output,
    Confirm,
}

enum Action {
    Continue,
    Cancel,
    Done,
}

/// 검사를 통과한 출력 계획: 생성 경로, 만들 링크(없으면 None), 사용자에게 알릴 참고 사항
struct OutputPlan {
    dst: PathBuf,
    link_name: String,
    link: Option<PathBuf>,
    notes: Vec<(&'static str, String)>,
}

enum OutputError {
    Empty,
    NoFileName,
    NoDir(PathBuf),
    SameAsOriginal,
    LinkIsOriginal(PathBuf),
}

impl OutputError {
    /// in_place_hint: 원본에 직접 적용하는 방법 안내 (대화형/CLI 에서 문구가 다르다)
    fn message(&self, in_place_hint: &str) -> String {
        match self {
            OutputError::Empty => "실행 파일 이름을 입력하세요.".into(),
            OutputError::NoFileName => "경로는 파일 이름으로 끝나야 합니다.".into(),
            OutputError::NoDir(d) => format!("디렉토리가 없습니다: {}", d.display()),
            OutputError::SameAsOriginal => format!("원본과 같은 경로입니다. {in_place_hint}"),
            OutputError::LinkIsOriginal(l) => format!(
                "{} 가 원본 바이너리라서 링크로 바꿀 수 없습니다. 다른 이름을 쓰세요.",
                tilde_path(l)
            ),
        }
    }
}

/// 실제 경로로 정규화한다. 파일이 아직 없어도 상위 디렉토리만 있으면 된다.
fn real_path(p: &Path) -> Option<PathBuf> {
    let parent = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    Some(fs::canonicalize(parent).ok()?.join(p.file_name()?))
}

/// 출력 이름을 검사해 생성 경로와 링크를 정한다 (대화형 UI 와 -o 옵션이 함께 사용).
/// 원본(대상, 패치 원본, antigravity.orig 백업)을 덮어쓰거나 링크로 바꾸는 경우를 막는다.
fn plan_output(bin_dir: &Path, target_bin: &Path, src_bin: &Path, name: &str) -> Result<OutputPlan, OutputError> {
    if name.is_empty() {
        return Err(OutputError::Empty);
    }
    let (dst, link_name) = output_paths(bin_dir, name);
    if name.ends_with('/') || dst.file_name().is_none() {
        return Err(OutputError::NoFileName);
    }
    let real_dst = real_path(&dst).ok_or_else(|| {
        OutputError::NoDir(match dst.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
            _ => PathBuf::from("."),
        })
    })?;
    let originals = [target_bin.to_path_buf(), src_bin.to_path_buf(), bin_dir.join("antigravity.orig")];
    if originals.contains(&real_dst) {
        return Err(OutputError::SameAsOriginal);
    }

    let mut notes = Vec::new();
    if real_dst.exists() {
        notes.push((S_DIM, "같은 이름의 기존 파일을 새로 덮어씁니다.".to_string()));
    }

    let mut link = local_bin_link(&link_name);
    if let Some(l) = &link {
        let real_link = real_path(l).unwrap_or_else(|| l.clone());
        if real_link == real_dst {
            // 결과물이 곧 ~/.local/bin/<이름> 이면 링크를 따로 만들지 않는다
            link = None;
        } else if originals.contains(&real_link) {
            return Err(OutputError::LinkIsOriginal(l.clone()));
        } else if l.exists() || l.is_symlink() {
            match fs::read_link(l) {
                Ok(t) if t == real_dst || t == dst => {}
                Ok(t) => notes.push((
                    S_WARN,
                    format!("{} 링크가 다른 파일({})을 가리키고 있어 교체됩니다.", tilde_path(l), tilde_path(&t)),
                )),
                Err(_) => notes.push((S_WARN, format!("{} 에 있는 일반 파일을 링크로 교체합니다.", tilde_path(l)))),
            }
        }
    }
    Ok(OutputPlan { dst, link_name, link, notes })
}

/// 대화형 설정의 결과: (적용할 패치, 출력 이름, in-place 여부)
type WizardResult = (Vec<&'static PatchSpec>, String, bool);

struct Wizard<'a> {
    src_bin: &'a Path,
    target_bin: &'a Path,
    bin_dir: &'a Path,
    version: &'a str,
    platform: String,
    color: bool,
    /// 각 패치를 이 바이너리에 실제로 적용할 수 있는지 (resolver 사전 실행 결과)
    avail: Vec<Result<(), String>>,
    selected: Vec<bool>,
    cursor: usize,
    scroll: usize,
    step: Step,
    out_choice: usize,
    name: Vec<char>,
    name_pos: usize,
    name_edited: bool,
    flash: Option<(&'static str, String)>,
    /// 터미널 높이가 낮을 때 빈 줄을 줄여 목록 공간을 확보
    compact: bool,
}

fn patch_index(id: &str) -> Option<usize> {
    PATCH_REGISTRY.iter().position(|p| p.id == id)
}

impl<'a> Wizard<'a> {
    fn new(src_bin: &'a Path, target_bin: &'a Path, bin_dir: &'a Path, version: &'a str, ctx: &BinaryContext) -> Self {
        let avail: Vec<Result<(), String>> = PATCH_REGISTRY.iter().map(|p| (p.resolver)(ctx).map(|_| ())).collect();
        let selected = PATCH_REGISTRY
            .iter()
            .zip(&avail)
            .map(|(p, a)| p.default_on && a.is_ok())
            .collect();
        let format = match ctx.format {
            Format::Elf64 => "ELF",
            Format::MachO64 => "Mach-O",
        };
        let arch = match ctx.arch {
            Arch::X86_64 => "x86_64",
            Arch::Arm64 => "arm64",
        };
        let color = env::var_os("NO_COLOR").is_none() && env::var("TERM").map_or(true, |t| t != "dumb");
        Wizard {
            src_bin,
            target_bin,
            bin_dir,
            version,
            platform: format!("{format} · {arch}"),
            color,
            avail,
            selected,
            cursor: 0,
            scroll: 0,
            step: Step::Patches,
            out_choice: 0,
            name: Vec::new(),
            name_pos: 0,
            name_edited: false,
            flash: None,
            compact: false,
        }
    }

    fn chosen(&self) -> Vec<&'static PatchSpec> {
        PATCH_REGISTRY
            .iter()
            .zip(&self.selected)
            .filter_map(|(p, &on)| on.then_some(p))
            .collect()
    }

    fn default_name(&self) -> &'static str {
        if patch_index("batch").is_some_and(|i| self.selected[i]) {
            "agy-batch"
        } else {
            "agy-patched"
        }
    }

    fn name_str(&self) -> String {
        let s: String = self.name.iter().collect();
        let s = s.trim().to_string();
        match (s.strip_prefix("~/"), env::var_os("HOME")) {
            (Some(rest), Some(home)) => PathBuf::from(home).join(rest).display().to_string(),
            _ => s,
        }
    }

    fn toggle(&mut self, i: usize) {
        if self.avail[i].is_err() {
            // 사유는 하단 상세 영역에 이미 표시된다
            self.flash = Some((S_WARN, format!("'{}' 패치는 이 바이너리에 적용할 수 없어 선택할 수 없습니다.", PATCH_REGISTRY[i].id)));
            return;
        }
        self.selected[i] = !self.selected[i];

        // batch 는 nodrip 과 함께 동작해야 하므로 두 패치를 연동한다.
        let (Some(b), Some(nd)) = (patch_index("batch"), patch_index("nodrip")) else {
            return;
        };
        if i == b && self.selected[b] && !self.selected[nd] && self.avail[nd].is_ok() {
            self.selected[nd] = true;
            self.flash = Some((S_ACCENT, "batch 는 nodrip 과 함께 동작하므로 nodrip 도 선택했습니다.".into()));
        } else if i == nd && !self.selected[nd] && self.selected[b] {
            self.selected[b] = false;
            self.flash = Some((S_ACCENT, "nodrip 을 해제하면 batch 도 함께 해제됩니다.".into()));
        }
    }

    fn toggle_all(&mut self) {
        let avail_idx: Vec<usize> = (0..PATCH_REGISTRY.len()).filter(|&i| self.avail[i].is_ok()).collect();
        let all_on = avail_idx.iter().all(|&i| self.selected[i]);
        for i in avail_idx {
            self.selected[i] = !all_on;
        }
    }

    fn output_plan(&self) -> Result<OutputPlan, OutputError> {
        plan_output(self.bin_dir, self.target_bin, self.src_bin, &self.name_str())
    }

    fn handle_key(&mut self, key: Key) -> Action {
        if key == Key::CtrlC {
            return Action::Cancel;
        }
        self.flash = None;
        let n = PATCH_REGISTRY.len();
        match self.step {
            Step::Patches => match key {
                Key::Esc | Key::Char('q') | Key::Char('Q') => return Action::Cancel,
                Key::Up | Key::Char('k') => self.cursor = (self.cursor + n - 1) % n,
                Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1) % n,
                Key::Home => self.cursor = 0,
                Key::End => self.cursor = n - 1,
                Key::Char(' ') => self.toggle(self.cursor),
                Key::Char('a') | Key::Char('A') => self.toggle_all(),
                Key::Char(c) if c.is_ascii_digit() => {
                    let idx = (c as u8 - b'0') as usize;
                    if (1..=n).contains(&idx) {
                        self.cursor = idx - 1;
                        self.toggle(idx - 1);
                    }
                }
                Key::Enter | Key::Right => {
                    if self.selected.iter().any(|&x| x) {
                        if !self.name_edited {
                            self.name = self.default_name().chars().collect();
                            self.name_pos = self.name.len();
                        }
                        self.step = Step::Output;
                    } else {
                        self.flash = Some((S_WARN, "적용할 패치를 하나 이상 선택하세요.".into()));
                    }
                }
                _ => {}
            },
            Step::Output => match key {
                Key::Esc => self.step = Step::Patches,
                Key::Up => self.out_choice = 0,
                Key::Down => self.out_choice = 1,
                Key::Enter => {
                    if self.out_choice == 1 {
                        self.step = Step::Confirm;
                    } else if self.output_plan().is_err() {
                        // 오류 내용은 이름 칸 아래에 이미 표시되어 있다
                    } else {
                        self.step = Step::Confirm;
                    }
                }
                Key::Left if self.out_choice == 0 => self.name_pos = self.name_pos.saturating_sub(1),
                Key::Right if self.out_choice == 0 => self.name_pos = (self.name_pos + 1).min(self.name.len()),
                Key::Home if self.out_choice == 0 => self.name_pos = 0,
                Key::End if self.out_choice == 0 => self.name_pos = self.name.len(),
                Key::Backspace if self.out_choice == 0 && self.name_pos > 0 => {
                    self.name_pos -= 1;
                    self.name.remove(self.name_pos);
                    self.name_edited = true;
                }
                Key::Delete if self.out_choice == 0 && self.name_pos < self.name.len() => {
                    self.name.remove(self.name_pos);
                    self.name_edited = true;
                }
                Key::Char(c) if self.out_choice == 0 && !c.is_control() => {
                    self.name.insert(self.name_pos, c);
                    self.name_pos += 1;
                    self.name_edited = true;
                }
                _ => {}
            },
            Step::Confirm => match key {
                Key::Esc | Key::Left => self.step = Step::Output,
                Key::Char('q') | Key::Char('Q') => return Action::Cancel,
                Key::Enter => return Action::Done,
                _ => {}
            },
        }
        Action::Continue
    }

    fn header(&self, w: usize) -> Vec<Line> {
        let mut lines = Vec::new();
        if !self.compact {
            lines.push(Line::new());
        }
        lines.push(
            Line::new()
                .s(S_PLAIN, " ")
                .s(S_ACCENT_B, "agy-cli-patch")
                .s(S_DIM, format!(" v{}", env!("CARGO_PKG_VERSION")))
                .with_right(Line::new().s(S_DIM, format!("{} ", self.platform)), w),
        );
        let ver = format!("  {}", self.version);
        let budget = w.saturating_sub(8 + str_width(&ver)).max(10);
        lines.push(
            Line::new()
                .s(S_DIM, " 대상  ")
                .s(S_PLAIN, truncate_start(&tilde_path(self.target_bin), budget))
                .s(S_DIM, ver),
        );
        if self.src_bin != self.target_bin {
            lines.push(
                Line::new()
                    .s(S_DIM, " 원본  ")
                    .s(S_PLAIN, truncate_start(&tilde_path(self.src_bin), w.saturating_sub(8)))
                    .s(S_DIM, "  (백업본에서 패치)"),
            );
        }
        if !self.compact {
            lines.push(Line::new());
        }

        let steps = [(Step::Patches, "패치 선택"), (Step::Output, "출력 방식"), (Step::Confirm, "확인")];
        let cur = steps.iter().position(|(s, _)| *s == self.step).unwrap_or(0);
        let mut line = Line::new().s(S_PLAIN, " ");
        for (i, (_, label)) in steps.iter().enumerate() {
            if i > 0 {
                line = line.s(S_DIM, "  ›  ");
            }
            let (num_style, label_style, mark) = if i < cur {
                (S_OK, S_DIM, "✓".to_string())
            } else if i == cur {
                (S_ACCENT_B, S_BOLD, (i + 1).to_string())
            } else {
                (S_DIM, S_DIM, (i + 1).to_string())
            };
            line = line.s(num_style, mark).s(label_style, format!(" {label}"));
        }
        lines.push(line);
        lines.push(rule(w));
        lines
    }

    /// 알림 메시지(있으면)와 키 안내 앞의 빈 줄
    fn flash_lines(&self) -> Vec<Line> {
        let mut lines = vec![Line::new()];
        if let Some((style, msg)) = &self.flash {
            lines.push(Line::new().s(style, format!(" {msg}")));
            lines.push(Line::new());
        }
        lines
    }

    fn id_width() -> usize {
        PATCH_REGISTRY.iter().map(|p| str_width(p.id)).max().unwrap_or(8) + 2
    }

    fn body_patches(&mut self, w: usize, room: usize) -> (Vec<Line>, Vec<Line>) {
        let idw = Self::id_width();
        let count = self.selected.iter().filter(|&&x| x).count();
        let mut top = vec![Line::new()
            .s(S_BOLD, " 적용할 패치를 고르세요")
            .with_right(Line::new().s(S_DIM, format!("{count}/{} 선택 ", PATCH_REGISTRY.len())), w)];
        if !self.compact {
            top.push(Line::new());
        }

        // 하단: 커서가 가리키는 패치의 상세 설명
        let spec = &PATCH_REGISTRY[self.cursor];
        let mut bottom = if self.compact { vec![rule(w)] } else { vec![Line::new(), rule(w)] };
        let desc_max = if self.compact { 2 } else { 3 };
        for l in wrap_text(spec.description, w.saturating_sub(3)).into_iter().take(desc_max) {
            bottom.push(Line::new().s(S_PLAIN, format!(" {l}")));
        }
        bottom.push(Line::new().s(S_DIM, " 심볼  ").s(S_DIM, spec.symbol));
        if let Err(e) = &self.avail[self.cursor] {
            bottom.push(Line::new().s(S_ERR, " 사용 불가  ").s(S_ERR, e.clone()));
        }
        bottom.extend(self.flash_lines());

        // 목록: 화면이 작으면 커서를 따라 스크롤
        let list_h = room.saturating_sub(top.len() + bottom.len()).max(1);
        if self.cursor < self.scroll {
            self.scroll = self.cursor;
        } else if self.cursor >= self.scroll + list_h {
            self.scroll = self.cursor + 1 - list_h;
        }
        // 화면이 커지면 위로 당겨 빈 줄 없이 채운다
        self.scroll = self.scroll.min(PATCH_REGISTRY.len().saturating_sub(list_h));
        let mut lines = top;
        let end = (self.scroll + list_h).min(PATCH_REGISTRY.len());
        for (i, p) in PATCH_REGISTRY.iter().enumerate().take(end).skip(self.scroll) {
            let is_cur = i == self.cursor;
            let ok = self.avail[i].is_ok();
            let pointer = if is_cur { (S_ACCENT_B, " ❯ ") } else { (S_PLAIN, "   ") };
            let check = match (ok, self.selected[i]) {
                (false, _) => (S_DIM, "✕ "),
                (true, true) => (S_OK, "◉ "),
                (true, false) => (S_DIM, "○ "),
            };
            let (id_style, title_style) = match (ok, is_cur) {
                (false, _) => (S_DIM, S_DIM),
                (true, true) => (S_ACCENT_B, S_BOLD),
                (true, false) => (S_ACCENT, S_PLAIN),
            };
            let pad = " ".repeat(idw.saturating_sub(str_width(p.id)));
            let mut line = Line::new()
                .s(pointer.0, pointer.1)
                .s(check.0, check.1)
                .s(id_style, format!("{}{pad}", p.id))
                .s(title_style, p.title);
            if !ok {
                line = line.s(S_DIM, "  (사용 불가)");
            }
            lines.push(line);
        }
        if self.scroll + list_h < PATCH_REGISTRY.len() {
            if let Some(last) = lines.last_mut() {
                *last = Line::new().s(S_DIM, format!("   … {}개 더", PATCH_REGISTRY.len() - self.scroll - list_h + 1));
            }
        }
        lines.extend(bottom);
        let footer = vec![key_hints(&[
            ("↑↓", "이동"),
            ("space", "선택"),
            ("a", "전체"),
            ("enter", "다음"),
            ("q", "종료"),
        ])];
        (lines, footer)
    }

    fn body_output(&self, w: usize) -> (Vec<Line>, Vec<Line>) {
        let mut lines = vec![Line::new().s(S_BOLD, " 결과물을 어떻게 만들까요?"), Line::new()];

        // 1) 새 실행 파일
        let sel0 = self.out_choice == 0;
        lines.push(
            Line::new()
                .s(if sel0 { S_ACCENT_B } else { S_PLAIN }, if sel0 { " ❯ " } else { "   " })
                .s(if sel0 { S_BOLD } else { S_PLAIN }, "새 실행 파일 만들기")
                .s(S_DIM, "   원본은 그대로 둡니다"),
        );
        let mut field = Line::new().s(S_DIM, "     이름  ");
        if sel0 {
            let before: String = self.name[..self.name_pos].iter().collect();
            let at = self.name.get(self.name_pos).map_or(" ".to_string(), |c| c.to_string());
            let after: String = self.name.get(self.name_pos + 1..).map_or(String::new(), |s| s.iter().collect());
            field = field.s(S_ACCENT_B, before).s(S_CARET, at).s(S_ACCENT_B, after);
        } else {
            field = field.s(S_PLAIN, self.name.iter().collect::<String>());
        }
        lines.push(field);
        let pw = w.saturating_sub(13);
        match self.output_plan() {
            Err(err) => {
                for l in wrap_text(&err.message("원본에 적용하려면 아래 in-place 를 고르세요."), w.saturating_sub(6)) {
                    lines.push(Line::new().s(S_ERR, format!("     {l}")));
                }
            }
            Ok(plan) => {
                lines.push(
                    Line::new()
                        .s(S_DIM, "     생성  ")
                        .s(S_PLAIN, truncate_start(&tilde_path(&plan.dst), pw)),
                );
                if let Some(link) = &plan.link {
                    lines.push(
                        Line::new()
                            .s(S_DIM, "     링크  ")
                            .s(S_PLAIN, truncate_start(&tilde_path(link), pw)),
                    );
                }
                for (style, note) in &plan.notes {
                    for l in wrap_text(note, w.saturating_sub(6)) {
                        lines.push(Line::new().s(style, format!("     {l}")));
                    }
                }
            }
        }
        lines.push(Line::new());

        // 2) in-place
        let sel1 = self.out_choice == 1;
        let backup = self.bin_dir.join("antigravity.orig");
        lines.push(
            Line::new()
                .s(if sel1 { S_ACCENT_B } else { S_PLAIN }, if sel1 { " ❯ " } else { "   " })
                .s(if sel1 { S_BOLD } else { S_PLAIN }, "기본 agy에 직접 덮어쓰기")
                .s(S_DIM, "   in-place"),
        );
        let backup_note = if backup.exists() { "  (이미 있음)" } else { "  (새로 만듦)" };
        lines.push(
            Line::new()
                .s(S_DIM, "     백업  ")
                .s(S_PLAIN, truncate_start(&tilde_path(&backup), pw.saturating_sub(14)))
                .s(S_DIM, backup_note),
        );
        for l in wrap_text("agy 자체 업데이트 시 패치가 사라지므로 다시 실행해야 합니다.", w.saturating_sub(6)) {
            lines.push(Line::new().s(S_DIM, format!("     {l}")));
        }
        lines.extend(self.flash_lines());

        let hints: &[(&str, &str)] = if sel0 {
            &[("↑↓", "방식"), ("←→", "커서"), ("enter", "다음"), ("esc", "뒤로"), ("ctrl+c", "종료")]
        } else {
            &[("↑↓", "방식"), ("enter", "다음"), ("esc", "뒤로"), ("ctrl+c", "종료")]
        };
        (lines, vec![key_hints(hints)])
    }

    fn body_confirm(&self, w: usize) -> (Vec<Line>, Vec<Line>) {
        let chosen = self.chosen();
        let idw = Self::id_width();
        let mut lines = vec![
            Line::new().s(S_BOLD, " 아래 내용으로 패치합니다"),
            Line::new(),
            Line::new().s(S_DIM, format!(" 적용할 패치 {}개", chosen.len())),
        ];
        for p in &chosen {
            let pad = " ".repeat(idw.saturating_sub(str_width(p.id)));
            lines.push(
                Line::new()
                    .s(S_OK, "   ✓ ")
                    .s(S_ACCENT, format!("{}{pad}", p.id))
                    .s(S_PLAIN, p.title),
            );
        }
        lines.push(Line::new());
        lines.push(Line::new().s(S_DIM, " 출력"));
        let pw = w.saturating_sub(10);
        if self.out_choice == 1 {
            let backup = self.bin_dir.join("antigravity.orig");
            lines.push(
                Line::new()
                    .s(S_DIM, "   덮어쓰기  ")
                    .s(S_PLAIN, truncate_start(&tilde_path(self.target_bin), pw)),
            );
            lines.push(
                Line::new()
                    .s(S_DIM, "   원본 백업  ")
                    .s(S_PLAIN, truncate_start(&tilde_path(&backup), pw)),
            );
        } else if let Ok(plan) = self.output_plan() {
            lines.push(
                Line::new()
                    .s(S_DIM, "   생성  ")
                    .s(S_PLAIN, truncate_start(&tilde_path(&plan.dst), pw)),
            );
            if let Some(link) = &plan.link {
                lines.push(
                    Line::new()
                        .s(S_DIM, "   링크  ")
                        .s(S_PLAIN, truncate_start(&tilde_path(link), pw)),
                );
            }
            for (style, note) in &plan.notes {
                for l in wrap_text(note, w.saturating_sub(4)) {
                    lines.push(Line::new().s(style, format!("   {l}")));
                }
            }
        }
        lines.extend(self.flash_lines());
        (lines, vec![key_hints(&[("enter", "패치 실행"), ("esc", "뒤로"), ("q", "종료")])])
    }

    fn render(&mut self, w: usize, h: usize) -> Vec<String> {
        // 마지막 열에 쓰면 일부 터미널에서 줄이 넘어가므로 한 칸 여유를 둔다
        let w = w.saturating_sub(1).max(20);
        self.compact = h < 26;
        let header = self.header(w);
        let room = h.saturating_sub(header.len() + 1);
        let (body, footer) = match self.step {
            Step::Patches => self.body_patches(w, room),
            Step::Output => self.body_output(w),
            Step::Confirm => self.body_confirm(w),
        };

        let mut all = header;
        all.extend(body);
        all.extend(footer);
        if all.len() > h {
            all.drain(h.saturating_sub(1)..all.len() - 1);
        }
        all.iter().map(|l| l.render(w, self.color)).collect()
    }
}

/// 대화형 설정 화면. 취소하면 None 을 돌려준다.
fn interactive_wizard(
    src_bin: &Path,
    target_bin: &Path,
    version: &str,
    ctx: &BinaryContext,
) -> Result<Option<WizardResult>, String> {
    let bin_dir = target_bin.parent().ok_or("상위 디렉토리를 확인할 수 없습니다.")?;
    let mut wiz = Wizard::new(src_bin, target_bin, bin_dir, version, ctx);
    let tui = Tui::enter()?;

    let mut last_size = (0, 0);
    let mut dirty = true;
    loop {
        let size = Tui::size();
        if dirty || size != last_size {
            tui.draw(&wiz.render(size.0, size.1));
            last_size = size;
            dirty = false;
        }
        for key in tui.read_keys() {
            dirty = true;
            match wiz.handle_key(key) {
                Action::Continue => {}
                Action::Cancel => return Ok(None),
                Action::Done => {
                    drop(tui);
                    let mut chosen = wiz.chosen();
                    // 안전장치: batch 는 nodrip 없이 적용하지 않는다
                    if chosen.iter().any(|p| p.id == "batch") && !chosen.iter().any(|p| p.id == "nodrip") {
                        chosen.insert(0, &PATCH_REGISTRY[0]);
                    }
                    return Ok(Some(if wiz.out_choice == 1 {
                        (chosen, String::new(), true)
                    } else {
                        (chosen, wiz.name_str(), false)
                    }));
                }
            }
        }
    }
}

fn parse_patch_list(spec_str: &str) -> Result<Vec<&'static PatchSpec>, String> {
    let items: Vec<&str> = spec_str.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    if items.is_empty() || items.contains(&"all") {
        // 'all' 은 기본 활성(default_on) 패치 전체. 기본 꺼짐 패치는 'all,release-notes' 처럼 명시한다.
        let mut v: Vec<&'static PatchSpec> = PATCH_REGISTRY.iter().filter(|p| p.default_on).collect();
        for item in &items {
            if let Some(spec) = PATCH_REGISTRY.iter().find(|p| p.id == *item && !p.default_on) {
                v.push(spec);
            }
        }
        return Ok(v);
    }
    let mut out = Vec::new();
    for item in items {
        let Some(spec) = PATCH_REGISTRY.iter().find(|p| p.id == item) else {
            let valid: Vec<&str> = PATCH_REGISTRY.iter().map(|p| p.id).collect();
            return Err(format!("알 수 없는 패치 ID: '{item}' (사용 가능: all, {})", valid.join(", ")));
        };
        out.push(spec);
    }
    Ok(out)
}

fn build_patched_binary(
    src_bin: &Path,
    ctx: &BinaryContext,
    patches: &[&'static PatchSpec],
    dst_bin: &Path,
    symlink_name: Option<&str>,
) -> Result<(), String> {
    let mut resolved = Vec::with_capacity(patches.len());
    for &spec in patches {
        let edits = (spec.resolver)(ctx)?;
        resolved.push((spec, edits));
    }

    copy_reflink(src_bin, dst_bin)?;

    {
        let mut file = OpenOptions::new()
            .write(true)
            .open(dst_bin)
            .map_err(|e| format!("패치 파일 쓰기 열기 실패 ({}): {e}", dst_bin.display()))?;

        for (_, edits) in &resolved {
            for edit in edits {
                file.seek(SeekFrom::Start(edit.offset as u64))
                    .map_err(|e| e.to_string())?;
                file.write_all(&edit.payload).map_err(|e| e.to_string())?;
            }
        }
    }

    println!(
        "\n[+] 패치 적용 내역 ({:?} / {:?}) -> {}",
        ctx.format,
        ctx.arch,
        dst_bin.display()
    );
    for (spec, edits) in &resolved {
        let offs: Vec<String> = edits.iter().map(|e| format!("0x{:x}", e.offset)).collect();
        println!("    - [{}] {} ({})", spec.id, spec.title, offs.join(", "));
    }

    resign_if_macho(dst_bin, ctx.format);

    if let Some(link_name) = symlink_name {
        if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
            let local_bin = home.join(".local/bin");
            let _ = fs::create_dir_all(&local_bin);
            let link = local_bin.join(link_name);
            if link.exists() || link.is_symlink() {
                let _ = fs::remove_file(&link);
            }
            symlink(dst_bin, &link)
                .map_err(|e| format!("심볼릭 링크 생성 실패 ({}): {e}", link.display()))?;
            println!("[+] 심볼릭 링크 연결 완료: {} -> {}", link.display(), dst_bin.display());
        }
    }

    Ok(())
}

fn print_help() {
    println!(
        "agy-cli-patch: Antigravity CLI (agy) 멀티플랫폼 자동 바이너리 패처 (Linux/macOS, x86_64/ARM64)

사용법:
  agy-cli-patch                           대화형(Interactive) 패치 선택 및 출력 파일명 지정
  agy-cli-patch --list                    사용 가능한 패치 ID 및 상세 설명 출력
  agy-cli-patch -p <목록> -o <파일명>     원하는 패치만 골라 지정한 이름으로 바이너리 생성
  agy-cli-patch --preset                  기본 프리셋 2종(agy-batch, agy-nodrip) 일괄 생성
  agy-cli-patch -p all --in-place         원본 백업(antigravity.orig) 후 기본 agy에 직접 적용
  agy-cli-patch --restore                 antigravity.orig 백업에서 원본 복구
  agy-cli-patch --notes                   패치 릴리즈 노트 출력

옵션:
  --bin <경로>       원본 antigravity 바이너리 경로 직접 지정 (미지정 시 자동 탐색)
  -p, --patches <ID> 쉼표로 구분된 패치 ID 또는 'all' (예: nodrip,batch,heading)
  -o, --output <이름> 생성할 실행 파일 이름 또는 경로
  --preset           프롬프트 없이 agy-batch와 agy-nodrip 생성
  --in-place         원본 백업 후 기본 바이너리 덮어쓰기
  --restore          --in-place 백업 복구
  --notes            패치 릴리즈 노트 출력 (agy 화면에 넣으려면 -p all,release-notes)
  -h, --help         도움말 출력"
    );
}

fn run() -> Result<(), String> {
    let mut bin_arg: Option<PathBuf> = None;
    let mut list_mode = false;
    let mut patches_arg: Option<String> = None;
    let mut output_arg: Option<String> = None;
    let mut preset_mode = false;
    let mut in_place = false;
    let mut restore_mode = false;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "--list" | "-l" => list_mode = true,
            "--notes" => {
                println!("{}", release_notes_text());
                return Ok(());
            }
            "--preset" => preset_mode = true,
            "--in-place" => in_place = true,
            "--restore" => restore_mode = true,
            "--bin" => {
                bin_arg = Some(PathBuf::from(
                    args.next().ok_or("--bin 옵션에 경로가 필요합니다.")?,
                ));
            }
            "-p" | "--patches" => {
                patches_arg = Some(args.next().ok_or("-p/--patches 옵션에 값이 필요합니다.")?);
            }
            "-o" | "--output" => {
                output_arg = Some(args.next().ok_or("-o/--output 옵션에 파일명이 필요합니다.")?);
            }
            other => return Err(format!("알 수 없는 옵션: {other} (--help 참고)")),
        }
    }

    if list_mode {
        println!("사용 가능한 패치 목록:");
        for (i, spec) in PATCH_REGISTRY.iter().enumerate() {
            println!("  {}. {:<14} : {}", i + 1, spec.id, spec.title);
            println!("     - 설명 : {}", spec.description);
            println!("     - 심볼 : {}", spec.symbol);
        }
        return Ok(());
    }

    let target_bin = match bin_arg {
        Some(p) => fs::canonicalize(&p).unwrap_or(p),
        None => detect_default_binary(),
    };

    if !target_bin.exists() {
        return Err(format!(
            "대상 바이너리를 찾을 수 없습니다: {}\n'--bin /path/to/antigravity' 옵션이나 AGY_BIN 환경변수로 지정해 주세요.",
            target_bin.display()
        ));
    }

    let bin_dir = target_bin.parent().ok_or("상위 디렉토리를 확인할 수 없습니다.")?;
    let backup_bin = bin_dir.join("antigravity.orig");

    if restore_mode {
        if !backup_bin.exists() {
            return Err(format!("백업 파일이 없습니다: {}", backup_bin.display()));
        }
        copy_reflink(&backup_bin, &target_bin)?;
        println!("[+] 원본 복구 완료: {} -> {}", backup_bin.display(), target_bin.display());
        return Ok(());
    }

    // 새 릴리즈 업데이트 시 backup_bin 자동 갱신
    if backup_bin.exists() && target_bin != backup_bin {
        let cur_mmap = MmapFile::open(&target_bin)?;
        let cur_ctx = BinaryContext::parse(cur_mmap.as_slice())?;
        if is_unpatched_cut(&cur_ctx)? {
            copy_reflink(&target_bin, &backup_bin)?;
        }
    }

    let src_bin = if target_bin != backup_bin && backup_bin.exists() {
        backup_bin.clone()
    } else {
        target_bin.clone()
    };

    // mise 설치 디렉토리명(예: 1.5.6)은 agy 자체 업데이트 후 실제 버전과 어긋날 수 있으므로
    // 바이너리가 보고하는 버전을 함께 출력한다.
    let target_version = binary_version(&target_bin);
    println!("[*] 대상 바이너리: {} (버전 {})", target_bin.display(), target_version);
    if src_bin != target_bin {
        println!("[*] 패치 원본:     {} (버전 {})", src_bin.display(), binary_version(&src_bin));
    }

    let mmap = MmapFile::open(&src_bin)?;
    let ctx = BinaryContext::parse(mmap.as_slice())?;

    let is_tty = unsafe { isatty(0) == 1 };
    if preset_mode
        || (!is_tty && patches_arg.is_none() && output_arg.is_none() && !in_place)
    {
        let nodrip_patches: Vec<&'static PatchSpec> =
            PATCH_REGISTRY.iter().filter(|p| p.default_on && p.id != "batch").collect();
        let batch_patches: Vec<&'static PatchSpec> =
            PATCH_REGISTRY.iter().filter(|p| p.default_on).collect();
        build_patched_binary(
            &src_bin,
            &ctx,
            &nodrip_patches,
            &bin_dir.join("agy-nodrip"),
            Some("agy-nodrip"),
        )?;
        build_patched_binary(
            &src_bin,
            &ctx,
            &batch_patches,
            &bin_dir.join("agy-batch"),
            Some("agy-batch"),
        )?;
        return Ok(());
    }

    let (chosen_patches, out_name, do_in_place) =
        if patches_arg.is_none() && output_arg.is_none() && !in_place {
            match interactive_wizard(&src_bin, &target_bin, &target_version, &ctx)? {
                Some(result) => result,
                None => {
                    println!("취소되었습니다.");
                    return Ok(());
                }
            }
        } else {
            let patches = parse_patch_list(patches_arg.as_deref().unwrap_or("all"))?;
            let default_out = if patches.iter().any(|p| p.id == "batch") {
                "agy-batch"
            } else {
                "agy-patched"
            };
            let name = output_arg.unwrap_or_else(|| default_out.to_string());
            (patches, name, in_place)
        };

    if do_in_place {
        if !backup_bin.exists() {
            copy_reflink(&src_bin, &backup_bin)?;
            println!("[+] 원본 백업 저장: {}", backup_bin.display());
        }
        let backup_mmap = MmapFile::open(&backup_bin)?;
        let backup_ctx = BinaryContext::parse(backup_mmap.as_slice())?;
        build_patched_binary(&backup_bin, &backup_ctx, &chosen_patches, &target_bin, None)?;
        println!("[+] 기본 agy 바이너리에 패치 적용 완료: {}", target_bin.display());
        return Ok(());
    }

    let plan = plan_output(bin_dir, &target_bin, &src_bin, &out_name)
        .map_err(|e| e.message("원본에 직접 적용하려면 --in-place 를 사용하세요."))?;
    for (style, note) in &plan.notes {
        if *style == S_WARN {
            println!("[!] {note}");
        }
    }

    build_patched_binary(
        &src_bin,
        &ctx,
        &chosen_patches,
        &plan.dst,
        plan.link.as_ref().map(|_| plan.link_name.as_str()),
    )
}

fn main() {
    if let Err(e) = run() {
        eprintln!("[!] 오류: {e}");
        process::exit(1);
    }
}
