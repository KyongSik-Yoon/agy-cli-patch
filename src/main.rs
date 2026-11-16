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
    fn sys_read(fd: i32, buf: *mut std::ffi::c_void, count: usize) -> isize;
    fn tcgetattr(fd: i32, termios_p: *mut Termios) -> i32;
    fn tcsetattr(fd: i32, optional_actions: i32, termios_p: *const Termios) -> i32;
    fn isatty(fd: i32) -> i32;
    fn signal(signum: i32, handler: usize) -> usize;
}

const SIGPIPE: i32 = 13;
const SIG_DFL: usize = 0;

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
    segments: Vec<(usize, usize, usize)>, // (file_off, va, file_size)
    funcs: HashMap<&'a str, (usize, usize)>,
    compact_tokens: u32,
    code_theme: String,
}

impl<'a> BinaryContext<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, String> {
        let mut segments = Vec::new();
        let (format, arch, text_va, text_off) = if &data[..4] == b"\x7fELF" {
            let e_machine = read_u16(data, 0x12);
            let arch = match e_machine {
                0x3e => Arch::X86_64,
                0xb7 => Arch::Arm64,
                other => return Err(format!("지원하지 않는 ELF 아키텍처입니다 (e_machine=0x{other:x}).")),
            };

            let e_phoff = read_u64(data, 0x20) as usize;
            let e_phentsize = read_u16(data, 0x36) as usize;
            let e_phnum = read_u16(data, 0x38) as usize;
            if e_phoff > 0 && e_phentsize >= 40 && e_phoff + e_phnum * e_phentsize <= data.len() {
                for i in 0..e_phnum {
                    let base = e_phoff + i * e_phentsize;
                    let p_type = read_u32(data, base);
                    if p_type == 1 {
                        // PT_LOAD
                        let p_offset = read_u64(data, base + 8) as usize;
                        let p_vaddr = read_u64(data, base + 16) as usize;
                        let p_filesz = read_u64(data, base + 32) as usize;
                        if p_filesz > 0 {
                            segments.push((p_offset, p_vaddr, p_filesz));
                        }
                    }
                }
            }

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
                    let vmaddr = read_u64(data, off + 24) as usize;
                    let fileoff = read_u64(data, off + 40) as usize;
                    let filesize = read_u64(data, off + 48) as usize;
                    if filesize > 0 {
                        segments.push((fileoff, vmaddr, filesize));
                    }

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
            "utils.GetCheckpointConfig",
            "config.applyFeatureProviderCheckpointOverrideConfig",
            "render.BuildHeader",
            "render.BannerWithInfo",
            "runtime.concatstring2",
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
            segments,
            funcs,
            compact_tokens: DEFAULT_COMPACT_TOKENS,
            code_theme: DEFAULT_CODE_THEME.to_string(),
        })
    }

    fn off_to_va(&self, off: usize) -> Option<usize> {
        if self.segments.is_empty() {
            return Some(off);
        }
        self.segments
            .iter()
            .find(|&&(file_off, _, size)| off >= file_off && off - file_off < size)
            .and_then(|&(file_off, va, _)| va.checked_add(off - file_off))
    }

    fn va_to_off(&self, addr: usize) -> Option<usize> {
        if self.segments.is_empty() {
            return Some(addr);
        }
        self.segments
            .iter()
            .find(|&&(_, va, size)| addr >= va && addr - va < size)
            .and_then(|&(file_off, va, _)| file_off.checked_add(addr - va))
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

// --- ARM64 명령어 인코딩/디코딩 (code-theme / compact / banner / release-notes 공용) ---

mod a64 {
    pub const NOP: u32 = 0xd503201f;

    pub fn rd(w: u32) -> u32 {
        w & 31
    }
    /// movz xRd, #imm16 (hw=0)
    pub fn is_movz(w: u32) -> bool {
        w & 0xffe0_0000 == 0xd280_0000
    }
    /// movk xRd, #imm16, lsl #(16*hw)
    pub fn is_movk(w: u32, hw: u32) -> bool {
        w & 0xffe0_0000 == 0xf280_0000 | (hw << 21)
    }
    pub fn imm16(w: u32) -> u32 {
        (w >> 5) & 0xffff
    }
    pub fn movz(rd: u32, imm: u32) -> u32 {
        0xd280_0000 | ((imm & 0xffff) << 5) | rd
    }
    pub fn movk16(rd: u32, imm: u32) -> u32 {
        0xf2a0_0000 | ((imm & 0xffff) << 5) | rd
    }
    pub fn is_adrp(w: u32) -> bool {
        w & 0x9f00_0000 == 0x9000_0000
    }
    /// adrp 가 가리키는 4KB 페이지 주소
    pub fn adrp_target(w: u32, pc: usize) -> usize {
        let imm = (((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3);
        let imm = ((imm as i64) << 43) >> 43; // 21비트 부호 확장
        ((pc as i64 & !0xfff) + (imm << 12)) as usize
    }
    pub fn adrp(rd: u32, pc: usize, target: usize) -> Result<u32, String> {
        let imm = (target as i64 >> 12) - (pc as i64 >> 12);
        if !(-(1 << 20)..(1 << 20)).contains(&imm) {
            return Err("ADRP 범위(±4GB) 초과".into());
        }
        let imm = imm as u32;
        Ok(0x9000_0000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7ffff) << 5) | rd)
    }
    /// add xRd, xRn, #imm12 (shift 0)
    pub fn is_add_imm(w: u32) -> bool {
        w & 0xffc0_0000 == 0x9100_0000
    }
    pub fn add_rn(w: u32) -> u32 {
        (w >> 5) & 31
    }
    pub fn add_imm12(w: u32) -> usize {
        ((w >> 10) & 0xfff) as usize
    }
    pub fn add_imm(rd: u32, rn: u32, imm: usize) -> u32 {
        0x9100_0000 | (((imm & 0xfff) as u32) << 10) | (rn << 5) | rd
    }
    fn branch26(op: u32, pc: usize, target: usize) -> Result<u32, String> {
        let delta = target as i64 - pc as i64;
        if delta % 4 != 0 || !(-(1 << 27)..(1 << 27)).contains(&delta) {
            return Err("B/BL 분기 범위(±128MB) 초과".into());
        }
        Ok(op | (((delta >> 2) as u32) & 0x03ff_ffff))
    }
    pub fn b(pc: usize, target: usize) -> Result<u32, String> {
        branch26(0x1400_0000, pc, target)
    }
    pub fn bl(pc: usize, target: usize) -> Result<u32, String> {
        branch26(0x9400_0000, pc, target)
    }
    pub fn is_b(w: u32) -> bool {
        w & 0xfc00_0000 == 0x1400_0000
    }
    pub fn is_bl(w: u32) -> bool {
        w & 0xfc00_0000 == 0x9400_0000
    }
    pub fn branch26_target(w: u32, pc: usize) -> usize {
        let imm = (((w & 0x03ff_ffff) as i64) << 38) >> 36;
        (pc as i64 + imm) as usize
    }
    /// b.cond: 조건 코드
    pub fn bcond(w: u32) -> Option<u32> {
        (w & 0xff00_0010 == 0x5400_0000).then_some(w & 0xf)
    }
    pub fn bcond_target(w: u32, pc: usize) -> usize {
        let imm = ((((w >> 5) & 0x7ffff) as i64) << 45) >> 43;
        (pc as i64 + imm) as usize
    }
    pub const COND_NE: u32 = 1;
    pub const COND_LO: u32 = 3;
    pub const COND_GT: u32 = 12;
    pub const BR_X16: u32 = 0xd61f_0200;
    pub const X16: u32 = 16;
}

fn word(data: &[u8], off: usize) -> u32 {
    read_u32(data, off)
}

fn words(insns: &[u32]) -> Vec<u8> {
    insns.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// movz/movk(lsl 16) 쌍을 32비트 값으로 디코드한다 (같은 레지스터일 때만).
fn a64_mov32_pair(data: &[u8], off: usize) -> Option<(u32, u32)> {
    let (w0, w1) = (word(data, off), word(data, off + 4));
    (a64::is_movz(w0) && a64::is_movk(w1, 1) && a64::rd(w0) == a64::rd(w1))
        .then(|| (a64::rd(w0), a64::imm16(w0) | (a64::imm16(w1) << 16)))
}

fn a64_mov32_pair_bytes(reg: u32, value: u32) -> Vec<u8> {
    words(&[a64::movz(reg, value & 0xffff), a64::movk16(reg, value >> 16)])
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

const DEFAULT_CODE_THEME: &str = "vs";
const CODE_THEME_PRESETS: &[&str] = &[
    "vs",
    "solarized-light",
    "bw",
    "github",
    "catppuccin-latte",
    "xcode",
];

fn parse_code_theme(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    let valid = !trimmed.is_empty()
        && trimmed.len() <= 32
        && trimmed
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !valid {
        return Err(format!(
            "유효하지 않은 코드 테마 이름입니다: '{raw}' (영문 소문자·숫자·하이픈·밑줄, 예: vs, solarized-light, bw)"
        ));
    }
    Ok(trimmed)
}

fn find_chroma_theme_offset(data: &[u8], theme: &str) -> Result<usize, String> {
    let prefix = b"<style name=\"";
    let needle = format!("<style name=\"{theme}\"");
    let nb = needle.as_bytes();
    if data.len() >= nb.len() {
        let limit = data.len() - nb.len();
        let mut i = 0usize;
        while i <= limit {
            if let Some(rel) = data[i..=limit].iter().position(|&b| b == nb[0]) {
                let pos = i + rel;
                if &data[pos..pos + nb.len()] == nb {
                    return Ok(pos + prefix.len());
                }
                i = pos + 1;
            } else {
                break;
            }
        }
    }
    Err(format!(
        "바이너리 내장 Chroma 스타일에서 '{theme}' 테마를 찾을 수 없습니다 (추천: {})",
        CODE_THEME_PRESETS.join(", ")
    ))
}

struct CodeThemeSite {
    lea_disp_off: usize,
    lea_next_off: usize,
    len_imm_off: usize,
}

/// ARM64: `"terminal"` 비교 직후 `adrp xP; add xP, xP, #lo; (orr|movz) xL, #len; ... stp xP, xL, [..]`
struct A64CodeThemeSite {
    adrp_off: usize,
    ptr_reg: u32,
    len_off: usize,
    len_reg: u32,
}

const A64_ORR_IMM6: u32 = 0xb27f_07e0; // orr xL, xzr, #0x6 (원본 "native" 길이)

fn find_code_theme_site_a64(ctx: &BinaryContext) -> Result<A64CodeThemeSite, String> {
    let (start, end) = ctx.get_func("render.glamourStyleForScheme")?;
    let d = ctx.data;
    // "terminal" = 0x6c61_6e69_6d72_6574 (little-endian 8바이트)
    let chunks = [0x6574u32, 0x6d72, 0x6e69, 0x6c61];
    let mut matches = Vec::new();
    let mut off = start;
    while off + 12 * 4 <= end {
        let w = |k: usize| word(d, off + k * 4);
        let r = a64::rd(w(0));
        let is_terminal = a64::is_movz(w(0))
            && a64::imm16(w(0)) == chunks[0]
            && (1..4).all(|k| a64::is_movk(w(k), k as u32) && a64::rd(w(k)) == r && a64::imm16(w(k)) == chunks[k]);
        let cmp_ok = w(4) & 0xffe0_fc1f == 0xeb00_001f && (w(4) >> 16) & 31 == r;
        if !(is_terminal && cmp_ok && a64::bcond(w(5)) == Some(a64::COND_NE)) {
            off += 4;
            continue;
        }
        let (adrp, add, len) = (w(6), w(7), w(8));
        let p = a64::rd(adrp);
        let l = a64::rd(len);
        let len_ok = (a64::is_movz(len) || len & !31 == A64_ORR_IMM6) && l != p;
        let stp_ok = (9..12).any(|k| {
            let s = w(k);
            s & 0xffc0_0000 == 0xa900_0000 && s & 31 == p && (s >> 10) & 31 == l
        });
        if a64::is_adrp(adrp) && a64::is_add_imm(add) && a64::rd(add) == p && a64::add_rn(add) == p && len_ok && stp_ok {
            matches.push(A64CodeThemeSite {
                adrp_off: off + 24,
                ptr_reg: p,
                len_off: off + 32,
                len_reg: l,
            });
        }
        off += 4;
    }
    if matches.len() != 1 {
        return Err(format!(
            "glamourStyleForScheme ARM64 terminal 테마 패턴 매칭 실패 (매칭 수: {})",
            matches.len()
        ));
    }
    Ok(matches.into_iter().next().unwrap())
}

fn detect_patched_code_theme_a64(ctx: &BinaryContext) -> Option<String> {
    let site = find_code_theme_site_a64(ctx).ok()?;
    let d = ctx.data;
    let pc = ctx.off_to_va(site.adrp_off)?;
    let str_va = a64::adrp_target(word(d, site.adrp_off), pc) + a64::add_imm12(word(d, site.adrp_off + 4));
    let len_w = word(d, site.len_off);
    let len = if a64::is_movz(len_w) { a64::imm16(len_w) as usize } else { 6 };
    let str_off = ctx.va_to_off(str_va)?;
    let s = std::str::from_utf8(d.get(str_off..str_off + len)?).ok()?;
    (s != "native").then(|| s.to_string())
}

fn resolve_code_theme_a64(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    let site = find_code_theme_site_a64(ctx)?;
    let theme_off = find_chroma_theme_offset(ctx.data, &ctx.code_theme)?;
    let theme_va = ctx
        .off_to_va(theme_off)
        .ok_or_else(|| "테마 문자열 가상주소 변환 실패".to_string())?;
    let pc = ctx
        .off_to_va(site.adrp_off)
        .ok_or_else(|| "ADRP 명령어 가상주소 변환 실패".to_string())?;
    Ok(vec![
        ByteEdit {
            offset: site.adrp_off,
            payload: words(&[
                a64::adrp(site.ptr_reg, pc, theme_va)?,
                a64::add_imm(site.ptr_reg, site.ptr_reg, theme_va & 0xfff),
            ]),
        },
        ByteEdit {
            offset: site.len_off,
            payload: words(&[a64::movz(site.len_reg, ctx.code_theme.len() as u32)]),
        },
    ])
}

fn find_code_theme_site(ctx: &BinaryContext) -> Result<CodeThemeSite, String> {
    let (start, end) = ctx.get_func("render.glamourStyleForScheme")?;
    let body = &ctx.data[start..end];
    let mut matches = Vec::new();
    for i in 0..body.len().saturating_sub(42) {
        if body[i] != 0x48
            || !(0xb8..=0xbf).contains(&body[i + 1])
            || &body[i + 2..i + 10] != b"terminal"
            || body[i + 10] != 0x48
            || body[i + 11] != 0x39
        {
            continue;
        }
        let lea_rel = if body[i + 13] == 0x0f && body[i + 14] == 0x85 {
            i + 19
        } else if body[i + 13] == 0x75 {
            i + 15
        } else {
            continue;
        };
        if lea_rel + 27 > body.len() {
            continue;
        }
        let mov_ptr = lea_rel + 7;
        let mov_len = lea_rel + 15;
        if &body[lea_rel..lea_rel + 3] != &[0x48, 0x8d, 0x05]
            || &body[mov_ptr..mov_ptr + 4] != &[0x48, 0x89, 0x84, 0x24]
            || &body[mov_len..mov_len + 4] != &[0x48, 0xc7, 0x84, 0x24]
        {
            continue;
        }
        let sp_ptr = read_u32(body, mov_ptr + 4);
        let sp_len = read_u32(body, mov_len + 4);
        let cur_len = read_u32(body, mov_len + 8);
        if sp_ptr.saturating_add(8) == sp_len && (1..=64).contains(&cur_len) {
            matches.push(CodeThemeSite {
                lea_disp_off: start + lea_rel + 3,
                lea_next_off: start + lea_rel + 7,
                len_imm_off: start + mov_len + 8,
            });
        }
    }
    if matches.len() != 1 {
        return Err(format!(
            "glamourStyleForScheme terminal 테마 패턴 매칭 실패 (매칭 수: {})",
            matches.len()
        ));
    }
    Ok(matches.into_iter().next().unwrap())
}

fn detect_patched_code_theme(ctx: &BinaryContext) -> Option<String> {
    if ctx.arch == Arch::Arm64 {
        return detect_patched_code_theme_a64(ctx);
    }
    let site = find_code_theme_site(ctx).ok()?;
    let disp = read_i32(ctx.data, site.lea_disp_off) as i64;
    let len = read_u32(ctx.data, site.len_imm_off) as usize;
    let pc_va = ctx.off_to_va(site.lea_next_off)? as i64;
    let str_va = usize::try_from(pc_va + disp).ok()?;
    let str_off = ctx.va_to_off(str_va)?;
    let s = std::str::from_utf8(ctx.data.get(str_off..str_off + len)?).ok()?;
    (s != "native").then(|| s.to_string())
}

fn resolve_code_theme(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    if ctx.arch == Arch::Arm64 {
        return resolve_code_theme_a64(ctx);
    }
    let site = find_code_theme_site(ctx)?;
    let theme_off = find_chroma_theme_offset(ctx.data, &ctx.code_theme)?;
    let theme_va = ctx
        .off_to_va(theme_off)
        .ok_or_else(|| "테마 문자열 가상주소 변환 실패".to_string())?;
    let pc_va = ctx
        .off_to_va(site.lea_next_off)
        .ok_or_else(|| "LEA 명령어 가상주소 변환 실패".to_string())?;
    let disp = i32::try_from((theme_va as i64) - (pc_va as i64))
        .map_err(|_| "RIP 상대 변위 범위 초과".to_string())?;
    Ok(vec![
        ByteEdit {
            offset: site.lea_disp_off,
            payload: disp.to_le_bytes().to_vec(),
        },
        ByteEdit {
            offset: site.len_imm_off,
            payload: (ctx.code_theme.len() as u32).to_le_bytes().to_vec(),
        },
    ])
}

const DEFAULT_COMPACT_TOKENS: u32 = 180_000;
const MIN_COMPACT_TOKENS: u32 = 32_000;
const MAX_COMPACT_TOKENS: u32 = 1_000_000;

fn parse_compact_tokens(raw: &str) -> Result<u32, String> {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|&c| c != '_' && c != ',')
        .collect();
    let err = || {
        format!(
            "컴팩션 토큰 임계값은 32k~1000k (32000~1000000) 범위여야 합니다: '{raw}' (예: 180k, 180000)"
        )
    };
    if cleaned.is_empty() {
        return Err(err());
    }

    let (num_str, mul): (&str, u64) = if let Some(s) = cleaned.strip_suffix(['k', 'K']) {
        (s, 1_000)
    } else if let Some(s) = cleaned.strip_suffix(['m', 'M']) {
        (s, 1_000_000)
    } else {
        (&cleaned, 1)
    };

    let base: u64 = num_str.parse().map_err(|_| err())?;
    let total = base.checked_mul(mul).ok_or_else(err)?;
    if total < MIN_COMPACT_TOKENS as u64 || total > MAX_COMPACT_TOKENS as u64 {
        return Err(err());
    }
    Ok(total as u32)
}

fn format_compact_tokens(tokens: u32) -> String {
    if tokens.is_multiple_of(1_000) {
        format!("{}k", tokens / 1_000)
    } else {
        tokens.to_string()
    }
}

/// 임계값이 들어 있는 자리. x86_64 는 32비트 즉치(imm32), ARM64 는 movz/movk 쌍(레지스터 유지).
enum CompactSlot {
    Imm32(usize),
    A64Pair { off: usize, reg: u32 },
}

struct CompactSites {
    override_branch_off: usize,
    override_patch: Vec<u8>,
    is_override_patched: bool,
    slots: [CompactSlot; 3],
    current_tokens: u32,
}

fn find_compact_sites(ctx: &BinaryContext) -> Result<CompactSites, String> {
    if ctx.arch == Arch::Arm64 {
        return find_compact_sites_a64(ctx);
    }

    let (ov_start, ov_end) = ctx.get_func("config.applyFeatureProviderCheckpointOverrideConfig")?;
    let ov_body = &ctx.data[ov_start..ov_end];
    let mut ov_matches = Vec::new();
    for i in 0..ov_body.len().saturating_sub(10) {
        let w = &ov_body[i..i + 10];
        if &w[0..4] == &[0xff, 0xd2, 0x84, 0xc0]
            && (&w[4..6] == &[0x75, 0x08] || &w[4..6] == &[0x90, 0x90])
            && &w[6..10] == &[0x48, 0x8b, 0x44, 0x24]
        {
            ov_matches.push((ov_start + i + 4, &w[4..6] == &[0x90, 0x90]));
        }
    }
    if ov_matches.len() != 1 {
        return Err(format!(
            "applyFeatureProviderCheckpointOverrideConfig 분기 패턴 매칭 실패 (매칭 수: {})",
            ov_matches.len()
        ));
    }
    let (override_branch_off, is_override_patched) = ov_matches[0];

    let (gc_start, gc_end) = ctx.get_func("utils.GetCheckpointConfig")?;
    let gc_body = &ctx.data[gc_start..gc_end];

    let mut limit_matches = Vec::new();
    for i in 0..gc_body.len().saturating_sub(14) {
        let w = &gc_body[i..i + 14];
        if &w[0..2] == &[0x81, 0xfa] && w[6] == 0xbe && &w[11..14] == &[0x0f, 0x42, 0xf2] {
            let v1 = read_u32(w, 2);
            let v2 = read_u32(w, 7);
            if v1 == v2 && (MIN_COMPACT_TOKENS..=MAX_COMPACT_TOKENS).contains(&v1) {
                limit_matches.push((gc_start + i + 2, gc_start + i + 7, v1));
            }
        }
    }
    if limit_matches.len() != 1 {
        return Err(format!(
            "GetCheckpointConfig 상한 패턴 매칭 실패 (매칭 수: {})",
            limit_matches.len()
        ));
    }
    let (slot1_off, slot2_off, current_tokens) = limit_matches[0];

    let mut fallback_matches = Vec::new();
    for i in 0..gc_body.len().saturating_sub(13) {
        let w = &gc_body[i..i + 13];
        if &w[0..2] == &[0x83, 0x7a]
            && &w[3..9] == &[0x00, 0x7f, 0x07, 0xc7, 0x40, 0x0c]
            && read_u32(w, 9) == current_tokens
        {
            fallback_matches.push(gc_start + i + 9);
        }
    }
    if fallback_matches.len() != 1 {
        return Err(format!(
            "GetCheckpointConfig fallback 패턴 매칭 실패 (매칭 수: {})",
            fallback_matches.len()
        ));
    }

    Ok(CompactSites {
        override_branch_off,
        override_patch: vec![0x90, 0x90],
        is_override_patched,
        slots: [
            CompactSlot::Imm32(slot1_off),
            CompactSlot::Imm32(slot2_off),
            CompactSlot::Imm32(fallback_matches[0]),
        ],
        current_tokens,
    })
}

const A64_TBNZ_W0_BIT0_SKIP2: u32 = 0x3700_0060; // tbnz w0, #0, +12

fn find_compact_sites_a64(ctx: &BinaryContext) -> Result<CompactSites, String> {
    let d = ctx.data;

    // blr xN; tbnz w0,#0,+12 (패치 후 nop); ldr x0,[sp,#..]; b ..
    // tbnz 를 지우면 feature provider 의 체크포인트 덮어쓰기를 건너뛰고 로컬 설정을 쓴다 (x86 jne → nop 과 같음).
    let (ov_start, ov_end) = ctx.get_func("config.applyFeatureProviderCheckpointOverrideConfig")?;
    let mut ov_matches = Vec::new();
    let mut off = ov_start;
    while off + 16 <= ov_end {
        let (w0, w1, w2, w3) = (word(d, off), word(d, off + 4), word(d, off + 8), word(d, off + 12));
        if w0 & 0xffff_fc1f == 0xd63f_0000
            && (w1 == A64_TBNZ_W0_BIT0_SKIP2 || w1 == a64::NOP)
            && w2 & 0xffc0_03ff == 0xf940_03e0
            && a64::is_b(w3)
        {
            ov_matches.push((off + 4, w1 == a64::NOP));
        }
        off += 4;
    }
    if ov_matches.len() != 1 {
        return Err(format!(
            "applyFeatureProviderCheckpointOverrideConfig ARM64 분기 패턴 매칭 실패 (매칭 수: {})",
            ov_matches.len()
        ));
    }
    let (override_branch_off, is_override_patched) = ov_matches[0];

    let (gc_start, gc_end) = ctx.get_func("utils.GetCheckpointConfig")?;

    // 상한: movz/movk xR=N; cmp wA, wR; movz/movk xR=N; csel x?, x?, xR, lo
    let mut limit_matches = Vec::new();
    let mut off = gc_start;
    while off + 24 <= gc_end {
        if let (Some((r1, v1)), Some((r2, v2))) = (a64_mov32_pair(d, off), a64_mov32_pair(d, off + 12)) {
            let cmp = word(d, off + 8);
            let csel = word(d, off + 20);
            if r1 == r2
                && v1 == v2
                && (MIN_COMPACT_TOKENS..=MAX_COMPACT_TOKENS).contains(&v1)
                && cmp & 0xffe0_fc1f == 0x6b00_001f
                && (cmp >> 16) & 31 == r1
                && csel & 0xffe0_0c00 == 0x9a80_0000
                && (csel >> 12) & 0xf == a64::COND_LO
                && (csel >> 16) & 31 == r1
            {
                limit_matches.push((off, off + 12, r1, v1));
            }
        }
        off += 4;
    }
    if limit_matches.len() != 1 {
        return Err(format!(
            "GetCheckpointConfig ARM64 상한 패턴 매칭 실패 (매칭 수: {})",
            limit_matches.len()
        ));
    }
    let (slot1_off, slot2_off, limit_reg, current_tokens) = limit_matches[0];

    // 폴백: b.gt +16; movz/movk xR=N; str wR, [x?, #0xc]
    let mut fallback_matches = Vec::new();
    let mut off = gc_start + 4;
    while off + 12 <= gc_end {
        let prev = word(d, off - 4);
        let skip_ok = a64::bcond(prev) == Some(a64::COND_GT) && a64::bcond_target(prev, off - 4) == off + 12;
        if let Some((r, v)) = a64_mov32_pair(d, off) {
            let st = word(d, off + 8);
            if skip_ok && v == current_tokens && st & 0xffff_fc00 == 0xb900_0c00 && st & 31 == r {
                fallback_matches.push((off, r));
            }
        }
        off += 4;
    }
    if fallback_matches.len() != 1 {
        return Err(format!(
            "GetCheckpointConfig ARM64 fallback 패턴 매칭 실패 (매칭 수: {})",
            fallback_matches.len()
        ));
    }
    let (slot3_off, fallback_reg) = fallback_matches[0];

    Ok(CompactSites {
        override_branch_off,
        override_patch: words(&[a64::NOP]),
        is_override_patched,
        slots: [
            CompactSlot::A64Pair { off: slot1_off, reg: limit_reg },
            CompactSlot::A64Pair { off: slot2_off, reg: limit_reg },
            CompactSlot::A64Pair { off: slot3_off, reg: fallback_reg },
        ],
        current_tokens,
    })
}

fn detect_patched_compact_tokens(ctx: &BinaryContext) -> Option<u32> {
    let sites = find_compact_sites(ctx).ok()?;
    sites.is_override_patched.then_some(sites.current_tokens)
}

fn resolve_compact(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    let sites = find_compact_sites(ctx)?;
    let mut edits = vec![ByteEdit {
        offset: sites.override_branch_off,
        payload: sites.override_patch,
    }];
    for slot in &sites.slots {
        edits.push(match *slot {
            CompactSlot::Imm32(off) => ByteEdit {
                offset: off,
                payload: ctx.compact_tokens.to_le_bytes().to_vec(),
            },
            CompactSlot::A64Pair { off, reg } => ByteEdit {
                offset: off,
                payload: a64_mov32_pair_bytes(reg, ctx.compact_tokens),
            },
        });
    }
    Ok(edits)
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

/// Mach-O ARM64: `__TEXT` 세그먼트(r-x) 안, 마지막 섹션 뒤의 페이지 정렬 패딩을 동굴로 쓴다.
/// 섹션 헤더로 위치를 정하므로 패치 후 내용이 바뀌어도 같은 자리를 돌려준다(재패치 가능).
/// Linux ELF ARM64 는 실행 세그먼트 바로 뒤에 RW 세그먼트가 붙어 있어 쓸 수 있는 패딩이 없다.
fn find_cave_a64(ctx: &BinaryContext) -> Result<usize, String> {
    if ctx.format != Format::MachO64 {
        return Err("ARM64 banner/release-notes 패치는 macOS(Mach-O)에서만 지원됩니다 (Linux ARM64 는 여유 공간 없음).".into());
    }
    let d = ctx.data;
    let ncmds = read_u32(d, 16) as usize;
    let mut off = 32usize;
    for _ in 0..ncmds {
        let cmd = read_u32(d, off);
        let cmdsize = read_u32(d, off + 4) as usize;
        let segname = &d[off + 8..off + 24];
        if cmd == 0x19 && segname.starts_with(b"__TEXT\0") {
            let seg_fileoff = read_u64(d, off + 40) as usize;
            let seg_end = seg_fileoff + read_u64(d, off + 48) as usize;
            let nsects = read_u32(d, off + 64) as usize;
            let mut last_end = seg_fileoff;
            for k in 0..nsects {
                let s = off + 72 + k * 80;
                let size = read_u64(d, s + 40) as usize;
                let sect_off = read_u32(d, s + 48) as usize;
                if sect_off != 0 {
                    last_end = last_end.max(sect_off + size);
                }
            }
            let cave = (last_end + 15) & !15;
            if seg_end < cave + CAVE_MIN {
                return Err(format!("__TEXT 세그먼트 끝 여유 공간이 부족합니다 ({}바이트 필요).", CAVE_MIN));
            }
            return Ok(cave);
        }
        off += cmdsize;
    }
    Err("Mach-O __TEXT 세그먼트를 찾을 수 없습니다.".into())
}

fn a64_va(ctx: &BinaryContext, off: usize) -> Result<usize, String> {
    ctx.off_to_va(off).ok_or_else(|| format!("가상주소 변환 실패 (@0x{off:x})"))
}

/// BannerWithInfo 채널 검사 (원본):
///   add x27, sp, #0xfff; add x27, x27, #..; ldp xP, xL, [x27]; cbz xL, skip
///   str x1, [sp, #..]; str x0, [sp, #..]; cmp xL, #6; b.ne fmt   ("stable" 검사)
/// 패치 후:
///   (같은 add 두 줄); adrp xP, chan; add xP, xP, #lo; (str 두 줄 유지); movz xL, #len; b fmt
/// 두 str 는 Sprintf 뒤 concatstring2 가 다시 읽는 제품명 슬롯이므로 반드시 남긴다(x86 과 같은 이유).
fn resolve_banner_a64(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    let (start, end) = ctx.get_func("render.BannerWithInfo")?;
    let cave = find_cave_a64(ctx)?;
    let chan = format!("patch v{}", env!("CARGO_PKG_VERSION")).into_bytes();
    assert!(chan.len() <= CAVE_NOTES_OFF - CAVE_CHAN_OFF);
    let chan_off = cave + CAVE_CHAN_OFF;
    let chan_va = a64_va(ctx, chan_off)?;

    let d = ctx.data;
    let is_str_sp = |w: u32| w & 0xffc0_03e0 == 0xf900_03e0;
    let mut matches = Vec::new();
    let mut off = start + 8;
    while off + 24 <= end {
        let w = |k: usize| word(d, off + k * 4);
        let x27_ok = word(d, off - 8) == 0x913f_fffb && word(d, off - 4) & 0xffc0_03ff == 0x9100_037b;
        if !(x27_ok && is_str_sp(w(2)) && is_str_sp(w(3))) {
            off += 4;
            continue;
        }
        // 원본 형태
        let (w0, w1, w4, w5) = (w(0), w(1), w(4), w(5));
        if w0 & 0xffff_83e0 == 0xa940_0360 && a64::bcond(w5) == Some(a64::COND_NE) {
            let (p, l) = (w0 & 31, (w0 >> 10) & 31);
            if w1 & 0xff00_001f == 0xb400_0000 | l && w4 == 0xf100_181f | (l << 5) {
                matches.push((off, p, l, a64::bcond_target(w5, off + 20)));
            }
        }
        // 이미 패치된 형태
        if a64::is_adrp(w0) && a64::is_add_imm(w1) && a64::rd(w1) == a64::rd(w0) && a64::add_rn(w1) == a64::rd(w0)
            && a64::is_movz(w4) && a64::is_b(w5)
        {
            let target = a64::branch26_target(w5, a64_va(ctx, off + 20)?);
            let target = ctx.va_to_off(target).ok_or("분기 대상 변환 실패")?;
            matches.push((off, a64::rd(w0), a64::rd(w4), target));
        }
        off += 4;
    }
    if matches.len() != 1 {
        return Err(format!("BannerWithInfo ARM64 채널 검사 패턴 매칭 실패 (매칭 수: {})", matches.len()));
    }
    let (site, p, l, fmt_off) = matches[0];
    let site_va = a64_va(ctx, site)?;
    Ok(vec![
        ByteEdit { offset: chan_off, payload: chan.clone() },
        ByteEdit {
            offset: site,
            payload: words(&[a64::adrp(p, site_va, chan_va)?, a64::add_imm(p, p, chan_va & 0xfff)]),
        },
        ByteEdit {
            offset: site + 16,
            payload: words(&[
                a64::movz(l, chan.len() as u32),
                a64::b(site_va + 20, a64_va(ctx, fmt_off)?)?,
            ]),
        },
    ])
}

/// BuildHeader 끝의 `"\n" + strings.Join(lines, "\n")` (concatstring2) 호출을
/// 동굴 트램펄린으로 돌려 세 번째 인자(릴리즈 노트)를 붙인 concatstring3 로 꼬리 분기한다.
///   tramp: adrp x5, notes; add x5, x5, #lo; movz x6, #len; adrp x16, concatstring3; add x16, x16, #lo; br x16
/// 동굴에서 concatstring3 까지는 b(±128MB) 범위를 넘으므로 x16(링커 예약 스크래치)으로 간접 분기한다.
/// bl 이 아닌 br 이라 LR 은 BuildHeader 복귀 주소 그대로이고, BuildHeader 는 이미 concatstring3 를
/// 직접 호출하므로 7워드 인자 스필 영역도 확보돼 있다.
fn resolve_release_notes_a64(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    let (bh_start, bh_end) = ctx.get_func("render.BuildHeader")?;
    let (concat2_start, _) = ctx.get_func("runtime.concatstring2")?;
    let (concat3_start, _) = ctx.get_func("runtime.concatstring3")?;
    let cave = find_cave_a64(ctx)?;

    let notes = format!("\n\n{}", release_notes_text()).into_bytes();
    if notes.len() > 0xffff {
        return Err("릴리즈 노트가 너무 깁니다.".into());
    }
    let notes_off = cave + CAVE_NOTES_OFF;
    let tramp_off = (notes_off + notes.len() + 15) & !15;
    if tramp_off + 24 > cave + CAVE_MIN {
        return Err("릴리즈 노트가 여유 공간을 초과합니다.".into());
    }
    let notes_va = a64_va(ctx, notes_off)?;
    let tramp_va = a64_va(ctx, tramp_off)?;
    let c3_va = a64_va(ctx, concat3_start)?;
    let tramp = words(&[
        a64::adrp(5, tramp_va, notes_va)?,
        a64::add_imm(5, 5, notes_va & 0xfff),
        a64::movz(6, notes.len() as u32),
        a64::adrp(a64::X16, tramp_va + 12, c3_va)?,
        a64::add_imm(a64::X16, a64::X16, c3_va & 0xfff),
        a64::BR_X16,
    ]);

    // orr x2, xzr, #1; mov x3, x0; mov x4, x1; mov x0, xzr; adrp x1, "\n"; add x1, x1, #lo; bl concatstring2
    let d = ctx.data;
    let concat2_va = a64_va(ctx, concat2_start)?;
    let mut matches = Vec::new();
    let mut off = bh_start;
    while off + 28 <= bh_end {
        let w = |k: usize| word(d, off + k * 4);
        if w(0) == 0xb240_03e2
            && w(1) == 0xaa00_03e3
            && w(2) == 0xaa01_03e4
            && w(3) == 0xaa1f_03e0
            && a64::is_adrp(w(4))
            && a64::rd(w(4)) == 1
            && w(5) & 0xffc0_03ff == 0x9100_0021
            && a64::is_bl(w(6))
        {
            let call = off + 24;
            // 다른 버전의 패처가 만든 트램펄린(노트 길이가 달라 위치가 다름)도 동굴 안이면 재패치를 허용한다
            let target = a64::branch26_target(w(6), a64_va(ctx, call)?);
            let target_off = ctx.va_to_off(target).unwrap_or(usize::MAX);
            if target == concat2_va || (cave..cave + CAVE_MIN).contains(&target_off) {
                matches.push(call);
            }
        }
        off += 4;
    }
    if matches.len() != 1 {
        return Err(format!("BuildHeader ARM64 concatstring2 패턴 매칭 실패 (매칭 수: {})", matches.len()));
    }
    let call = matches[0];
    Ok(vec![
        ByteEdit { offset: notes_off, payload: notes },
        ByteEdit { offset: tramp_off, payload: tramp },
        ByteEdit {
            offset: call,
            payload: words(&[a64::bl(a64_va(ctx, call)?, tramp_va)?]),
        },
    ])
}

fn resolve_banner(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    match ctx.arch {
        Arch::X86_64 => {
            let (bwi_start, bwi_end) = ctx.get_func("render.BannerWithInfo")?;
            let cave_offset = find_cave(ctx)?;

            // 제품명 옆 괄호 안에 표시: "Antigravity CLI 1.5.7 (patch v0.2.3)"
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
        Arch::Arm64 => resolve_banner_a64(ctx),
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
        ("code-theme", "readable code block theme for terminal colorScheme (--code-theme vs)"),
        ("compact", "custom auto-compaction token limit (--compact 180k)"),
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
        Arch::Arm64 => resolve_release_notes_a64(ctx),
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
        id: "code-theme",
        title: "터미널 스킴 코드 블록 가독성 개선 (Terminal Code Theme)",
        description: "colorScheme: terminal 사용 시 흐린 회색(#d0d0d0)으로 묻히는 코드 블록 테마(native)를 선명한 테마(기본 vs)로 교체",
        symbol: "render.glamourStyleForScheme",
        default_on: true,
        resolver: resolve_code_theme,
    },
    PatchSpec {
        id: "compact",
        title: "자동 컴팩션 토큰 임계값 변경 (Auto-Compact Limit)",
        description: "내장 자동 컴팩션(CHECKPOINT) 발동 기준(기본 256k)을 원하는 토큰 수(기본 180k, 32k~1000k)로 변경 (기본 꺼짐)",
        symbol: "utils.GetCheckpointConfig",
        default_on: false,
        resolver: resolve_compact,
    },
    PatchSpec {
        id: "banner",
        title: "제품명 옆 패치 버전 표시 (Patch Version Tag)",
        description: "상단 'Antigravity CLI 1.5.7' 옆에 '(patch v0.2.3)' 형태로 패치 버전 표시",
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
        let n = unsafe { sys_read(0, buf.as_mut_ptr().cast(), buf.len()) };
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
    LinkIsNotSymlink(PathBuf),
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
            OutputError::LinkIsNotSymlink(l) => format!(
                "{} 에 링크가 아닌 파일이 있어 덮어쓸 수 없습니다. 다른 이름을 쓰거나 직접 옮긴 뒤 다시 실행하세요.",
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
                // 일반 파일·디렉토리: 사용자가 쓰던 다른 프로그램일 수 있으므로 지우지 않는다
                Err(_) => return Err(OutputError::LinkIsNotSymlink(l.clone())),
            }
        }
    }
    Ok(OutputPlan { dst, link_name, link, notes })
}

/// 대화형 설정의 결과: (적용할 패치, 출력 이름, in-place 여부, 컴팩션 토큰 한도, 코드 블록 테마)
type WizardResult = (Vec<&'static PatchSpec>, String, bool, u32, String);

struct Wizard<'a> {
    src_bin: &'a Path,
    target_bin: &'a Path,
    bin_dir: &'a Path,
    raw_data: &'a [u8],
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
    compact_tokens: u32,
    editing_compact: bool,
    compact_buf: Vec<char>,
    compact_pos: usize,
    code_theme: String,
    editing_theme: bool,
    theme_buf: Vec<char>,
    theme_pos: usize,
}

fn patch_index(id: &str) -> Option<usize> {
    PATCH_REGISTRY.iter().position(|p| p.id == id)
}

fn edit_inline_buffer(buf: &mut Vec<char>, pos: &mut usize, max_len: usize, key: &Key) -> Option<bool> {
    match key {
        Key::Esc => return Some(false),
        Key::Enter => return Some(true),
        Key::Left => *pos = pos.saturating_sub(1),
        Key::Right => *pos = (*pos + 1).min(buf.len()),
        Key::Home => *pos = 0,
        Key::End => *pos = buf.len(),
        Key::Backspace if *pos > 0 => {
            *pos -= 1;
            buf.remove(*pos);
        }
        Key::Delete if *pos < buf.len() => {
            buf.remove(*pos);
        }
        Key::Char(c) if !c.is_control() => {
            if buf.len() < max_len {
                buf.insert(*pos, *c);
                *pos += 1;
            }
        }
        _ => {}
    }
    None
}

fn append_inline_param(
    line: Line,
    editing: bool,
    buf: &[char],
    pos: usize,
    value: &str,
    selected: bool,
) -> Line {
    if editing {
        let before: String = buf[..pos].iter().collect();
        let at = buf.get(pos).map_or(" ".to_string(), |c| c.to_string());
        let after: String = buf.get(pos + 1..).map_or(String::new(), |s| s.iter().collect());
        line.s(S_DIM, "  [")
            .s(S_ACCENT_B, before)
            .s(S_CARET, at)
            .s(S_ACCENT_B, after)
            .s(S_DIM, "]")
    } else {
        line.s(if selected { S_ACCENT } else { S_DIM }, format!("  [{value}]"))
    }
}

impl<'a> Wizard<'a> {
    fn new(src_bin: &'a Path, target_bin: &'a Path, bin_dir: &'a Path, version: &'a str, ctx: &'a BinaryContext) -> Self {
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
            raw_data: ctx.data,
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
            compact_tokens: detect_patched_compact_tokens(ctx).unwrap_or(ctx.compact_tokens),
            editing_compact: false,
            compact_buf: Vec::new(),
            compact_pos: 0,
            code_theme: detect_patched_code_theme(ctx).unwrap_or_else(|| ctx.code_theme.clone()),
            editing_theme: false,
            theme_buf: Vec::new(),
            theme_pos: 0,
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

    fn adjust_compact_tokens(&mut self, delta: i32) {
        let Some(ci) = patch_index("compact") else {
            return;
        };
        if self.avail[ci].is_err() {
            self.flash = Some((S_WARN, "'compact' 패치는 이 바이너리에 적용할 수 없습니다.".into()));
            return;
        }
        let next = if delta.is_negative() {
            self.compact_tokens.saturating_sub(delta.unsigned_abs())
        } else {
            self.compact_tokens.saturating_add(delta as u32)
        }
        .clamp(MIN_COMPACT_TOKENS, MAX_COMPACT_TOKENS);
        self.compact_tokens = next;
        self.selected[ci] = true;
        self.flash = Some((
            S_ACCENT,
            format!("컴팩션 임계값: {} ({} 토큰)", format_compact_tokens(next), next),
        ));
    }

    fn adjust_code_theme(&mut self, delta: isize) {
        let Some(ti) = patch_index("code-theme") else {
            return;
        };
        if self.avail[ti].is_err() {
            self.flash = Some((S_WARN, "'code-theme' 패치는 이 바이너리에 적용할 수 없습니다.".into()));
            return;
        }
        let len = CODE_THEME_PRESETS.len() as isize;
        let cur_idx = CODE_THEME_PRESETS
            .iter()
            .position(|&p| p == self.code_theme)
            .map(|i| i as isize);
        let next_idx = match cur_idx {
            Some(i) => (i + delta).rem_euclid(len) as usize,
            None => if delta < 0 { CODE_THEME_PRESETS.len() - 1 } else { 0 },
        };
        let next = CODE_THEME_PRESETS[next_idx];
        self.code_theme = next.to_string();
        self.selected[ti] = true;
        self.flash = Some((S_ACCENT, format!("코드 블록 테마: {next}")));
    }

    fn handle_key(&mut self, key: Key) -> Action {
        if key == Key::CtrlC {
            return Action::Cancel;
        }
        self.flash = None;
        let n = PATCH_REGISTRY.len();
        match self.step {
            Step::Patches => {
                if self.editing_compact {
                    match edit_inline_buffer(&mut self.compact_buf, &mut self.compact_pos, 16, &key) {
                        Some(false) => self.editing_compact = false,
                        Some(true) => {
                            let raw: String = self.compact_buf.iter().collect();
                            match parse_compact_tokens(&raw) {
                                Ok(tokens) => {
                                    self.compact_tokens = tokens;
                                    self.editing_compact = false;
                                    if let Some(ci) = patch_index("compact") {
                                        if self.avail[ci].is_ok() {
                                            self.selected[ci] = true;
                                        }
                                    }
                                    self.flash = Some((
                                        S_OK,
                                        format!(
                                            "컴팩션 임계값이 {} ({} 토큰)으로 설정되었습니다.",
                                            format_compact_tokens(tokens),
                                            tokens
                                        ),
                                    ));
                                }
                                Err(err) => self.flash = Some((S_ERR, err)),
                            }
                        }
                        None => {}
                    }
                    return Action::Continue;
                }
                if self.editing_theme {
                    match edit_inline_buffer(&mut self.theme_buf, &mut self.theme_pos, 32, &key) {
                        Some(false) => self.editing_theme = false,
                        Some(true) => {
                            let raw: String = self.theme_buf.iter().collect();
                            let parsed = parse_code_theme(&raw).and_then(|theme| {
                                find_chroma_theme_offset(self.raw_data, &theme)?;
                                Ok(theme)
                            });
                            match parsed {
                                Ok(theme) => {
                                    self.code_theme = theme.clone();
                                    self.editing_theme = false;
                                    if let Some(ti) = patch_index("code-theme") {
                                        if self.avail[ti].is_ok() {
                                            self.selected[ti] = true;
                                        }
                                    }
                                    self.flash = Some((
                                        S_OK,
                                        format!("코드 블록 테마가 '{theme}'(으)로 설정되었습니다."),
                                    ));
                                }
                                Err(err) => self.flash = Some((S_ERR, err)),
                            }
                        }
                        None => {}
                    }
                    return Action::Continue;
                }

                let on_compact = PATCH_REGISTRY.get(self.cursor).is_some_and(|p| p.id == "compact");
                let on_theme = PATCH_REGISTRY.get(self.cursor).is_some_and(|p| p.id == "code-theme");
                match key {
                    Key::Esc | Key::Char('q') | Key::Char('Q') => return Action::Cancel,
                    Key::Up | Key::Char('k') => self.cursor = (self.cursor + n - 1) % n,
                    Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1) % n,
                    Key::Home => self.cursor = 0,
                    Key::End => self.cursor = n - 1,
                    Key::Char(' ') => self.toggle(self.cursor),
                    Key::Char('a') | Key::Char('A') => self.toggle_all(),
                    Key::Char('-') | Key::Char('[') if on_compact => self.adjust_compact_tokens(-10_000),
                    Key::Char('+') | Key::Char('=') | Key::Char(']') if on_compact => {
                        self.adjust_compact_tokens(10_000)
                    }
                    Key::Char('e') | Key::Char('E') if on_compact => {
                        if self.avail[self.cursor].is_err() {
                            self.flash = Some((
                                S_WARN,
                                "'compact' 패치는 이 바이너리에 적용할 수 없습니다.".into(),
                            ));
                        } else {
                            self.compact_buf =
                                format_compact_tokens(self.compact_tokens).chars().collect();
                            self.compact_pos = self.compact_buf.len();
                            self.editing_compact = true;
                        }
                    }
                    Key::Char('-') | Key::Char('[') if on_theme => self.adjust_code_theme(-1),
                    Key::Char('+') | Key::Char('=') | Key::Char(']') if on_theme => {
                        self.adjust_code_theme(1)
                    }
                    Key::Char('e') | Key::Char('E') if on_theme => {
                        if self.avail[self.cursor].is_err() {
                            self.flash = Some((
                                S_WARN,
                                "'code-theme' 패치는 이 바이너리에 적용할 수 없습니다.".into(),
                            ));
                        } else {
                            self.theme_buf = self.code_theme.chars().collect();
                            self.theme_pos = self.theme_buf.len();
                            self.editing_theme = true;
                        }
                    }
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
                }
            }
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
            if p.id == "compact" && ok {
                line = append_inline_param(
                    line,
                    self.editing_compact,
                    &self.compact_buf,
                    self.compact_pos,
                    &format_compact_tokens(self.compact_tokens),
                    self.selected[i],
                );
            } else if p.id == "code-theme" && ok {
                line = append_inline_param(
                    line,
                    self.editing_theme,
                    &self.theme_buf,
                    self.theme_pos,
                    &self.code_theme,
                    self.selected[i],
                );
            }
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
        let on_compact = PATCH_REGISTRY.get(self.cursor).is_some_and(|p| p.id == "compact");
        let on_theme = PATCH_REGISTRY.get(self.cursor).is_some_and(|p| p.id == "code-theme");
        let footer = if self.editing_compact || self.editing_theme {
            vec![key_hints(&[
                ("←→", "커서"),
                ("enter", "확정"),
                ("esc", "취소"),
            ])]
        } else if on_compact {
            vec![key_hints(&[
                ("↑↓", "이동"),
                ("space", "선택"),
                ("-/+", "±10k"),
                ("e", "수치"),
                ("enter", "다음"),
                ("q", "종료"),
            ])]
        } else if on_theme {
            vec![key_hints(&[
                ("↑↓", "이동"),
                ("space", "선택"),
                ("-/+", "테마"),
                ("e", "직접입력"),
                ("enter", "다음"),
                ("q", "종료"),
            ])]
        } else {
            vec![key_hints(&[
                ("↑↓", "이동"),
                ("space", "선택"),
                ("a", "전체"),
                ("enter", "다음"),
                ("q", "종료"),
            ])]
        };
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
            let mut l = Line::new()
                .s(S_OK, "   ✓ ")
                .s(S_ACCENT, format!("{}{pad}", p.id))
                .s(S_PLAIN, p.title);
            if p.id == "compact" {
                l = l.s(
                    S_ACCENT,
                    format!("  [{}]", format_compact_tokens(self.compact_tokens)),
                );
            } else if p.id == "code-theme" {
                l = l.s(S_ACCENT, format!("  [{}]", self.code_theme));
            }
            lines.push(l);
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
        self.compact = h < 27;
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
                        (chosen, String::new(), true, wiz.compact_tokens, wiz.code_theme)
                    } else {
                        (chosen, wiz.name_str(), false, wiz.compact_tokens, wiz.code_theme)
                    }));
                }
            }
        }
    }
}

fn apply_inline_patch_arg(
    id: &str,
    val: Option<&str>,
    compact_override: &mut Option<u32>,
    code_theme_override: &mut Option<String>,
) -> Result<(), String> {
    if let Some(raw_val) = val {
        match id {
            "compact" => *compact_override = Some(parse_compact_tokens(raw_val)?),
            "code-theme" => *code_theme_override = Some(parse_code_theme(raw_val)?),
            _ => return Err(format!("'{id}' 패치는 '=값' 인자를 지원하지 않습니다.")),
        }
    }
    Ok(())
}

fn parse_patch_list(
    spec_str: &str,
    compact_override: &mut Option<u32>,
    code_theme_override: &mut Option<String>,
) -> Result<Vec<&'static PatchSpec>, String> {
    let items: Vec<&str> = spec_str.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    if items.is_empty() || items.contains(&"all") {
        // 'all' 은 기본 활성(default_on) 패치 전체. 기본 꺼짐 패치는 'all,release-notes' 나 'all,compact=180k' 처럼 명시한다.
        let mut v: Vec<&'static PatchSpec> = PATCH_REGISTRY.iter().filter(|p| p.default_on).collect();
        for item in &items {
            let (id, val) = item.split_once('=').map_or((*item, None), |(k, rhs)| (k.trim(), Some(rhs.trim())));
            apply_inline_patch_arg(id, val, compact_override, code_theme_override)?;
            if let Some(spec) = PATCH_REGISTRY.iter().find(|p| p.id == id && !p.default_on) {
                if !v.iter().any(|p| p.id == spec.id) {
                    v.push(spec);
                }
            }
        }
        return Ok(v);
    }
    let mut out = Vec::new();
    for item in items {
        let (id, val) = item.split_once('=').map_or((item, None), |(k, rhs)| (k.trim(), Some(rhs.trim())));
        apply_inline_patch_arg(id, val, compact_override, code_theme_override)?;
        let Some(spec) = PATCH_REGISTRY.iter().find(|p| p.id == id) else {
            let valid: Vec<&str> = PATCH_REGISTRY.iter().map(|p| p.id).collect();
            return Err(format!("알 수 없는 패치 ID: '{id}' (사용 가능: all, {})", valid.join(", ")));
        };
        if !out.iter().any(|p: &&PatchSpec| p.id == spec.id) {
            out.push(spec);
        }
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
    // 최후 방어선: ~/.local/bin 에 링크가 아닌 파일이 있으면 아무것도 쓰기 전에 중단한다
    let link = symlink_name.and_then(local_bin_link);
    if let Some(l) = &link {
        if l.exists() && !l.is_symlink() {
            return Err(OutputError::LinkIsNotSymlink(l.clone()).message(""));
        }
    }

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
        if spec.id == "compact" {
            println!(
                "    - [{}] {} [{} = {} tokens] ({})",
                spec.id,
                spec.title,
                format_compact_tokens(ctx.compact_tokens),
                ctx.compact_tokens,
                offs.join(", ")
            );
        } else if spec.id == "code-theme" {
            println!(
                "    - [{}] {} [theme = {}] ({})",
                spec.id,
                spec.title,
                ctx.code_theme,
                offs.join(", ")
            );
        } else {
            println!("    - [{}] {} ({})", spec.id, spec.title, offs.join(", "));
        }
    }

    resign_if_macho(dst_bin, ctx.format);

    if let Some(link) = link {
        if let Some(local_bin) = link.parent() {
            let _ = fs::create_dir_all(local_bin);
        }
        if link.is_symlink() {
            let _ = fs::remove_file(&link);
        }
        symlink(dst_bin, &link).map_err(|e| format!("심볼릭 링크 생성 실패 ({}): {e}", link.display()))?;
        println!("[+] 심볼릭 링크 연결 완료: {} -> {}", link.display(), dst_bin.display());
    }

    Ok(())
}

const CLI_IN_PLACE_HINT: &str = "원본에 직접 적용하려면 --in-place 를 사용하세요.";

/// plan_output() 결과대로 바이너리를 만든다. 경고성 참고 사항은 먼저 출력한다.
fn build_from_plan(
    src_bin: &Path,
    ctx: &BinaryContext,
    patches: &[&'static PatchSpec],
    plan: &OutputPlan,
) -> Result<(), String> {
    for (style, note) in &plan.notes {
        if *style == S_WARN {
            println!("[!] {note}");
        }
    }
    build_patched_binary(
        src_bin,
        ctx,
        patches,
        &plan.dst,
        plan.link.as_ref().map(|_| plan.link_name.as_str()),
    )
}

fn print_help() {
    println!(
        "agy-cli-patch: Antigravity CLI (agy) 멀티플랫폼 자동 바이너리 패처 (Linux/macOS, x86_64/ARM64)

사용법:
  agy-cli-patch                           대화형(Interactive) 패치 선택 및 출력 파일명 지정
  agy-cli-patch --list                    사용 가능한 패치 ID 및 상세 설명 출력
  agy-cli-patch -p <목록> -o <파일명>     원하는 패치만 골라 지정한 이름으로 바이너리 생성
  agy-cli-patch -p all --compact 180k -o agy-batch  자동 컴팩션 임계값을 180k 토큰으로 변경
  agy-cli-patch -p all --code-theme solarized-light -o agy-batch  코드 블록 테마 변경
  agy-cli-patch --preset                  기본 프리셋 2종(agy-batch, agy-nodrip) 일괄 생성
  agy-cli-patch -p all --in-place         원본 백업(antigravity.orig) 후 기본 agy에 직접 적용
  agy-cli-patch --restore                 antigravity.orig 백업에서 원본 복구
  agy-cli-patch --notes                   패치 릴리즈 노트 출력

옵션:
  --bin <경로>              원본 antigravity 바이너리 경로 직접 지정 (미지정 시 자동 탐색)
  -p, --patches <ID>        쉼표로 구분된 패치 ID 또는 'all' (예: nodrip,batch,compact=180k)
  --compact <토큰>          자동 컴팩션 토큰 임계값 지정 (32k~1000k, 예: 180k, 180000; 지정 시 compact 자동 활성화)
  --code-theme <테마>       terminal 스킴 코드 블록 Chroma 테마 지정 (기본: vs, 예: vs, solarized-light, bw)
  -o, --output <이름>       생성할 실행 파일 이름 또는 경로
  --preset                  프롬프트 없이 agy-batch와 agy-nodrip 생성
  --in-place                원본 백업 후 기본 바이너리 덮어쓰기
  --restore                 --in-place 백업 복구
  --notes                   패치 릴리즈 노트 출력 (agy 화면에 넣으려면 -p all,release-notes)
  -h, --help                도움말 출력"
    );
}

fn ensure_patch_selected(patches: &mut Vec<&'static PatchSpec>, id: &str) {
    if let Some(spec) = PATCH_REGISTRY.iter().find(|p| p.id == id) {
        if !patches.iter().any(|p| p.id == id) {
            patches.push(spec);
        }
    }
}

fn run() -> Result<(), String> {
    let mut bin_arg: Option<PathBuf> = None;
    let mut list_mode = false;
    let mut patches_arg: Option<String> = None;
    let mut output_arg: Option<String> = None;
    let mut compact_arg: Option<u32> = None;
    let mut code_theme_arg: Option<String> = None;
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
            "--compact" | "--compact-tokens" => {
                let raw = args.next().ok_or("--compact 옵션에 토큰 수치(예: 180k)가 필요합니다.")?;
                compact_arg = Some(parse_compact_tokens(&raw)?);
            }
            "--code-theme" => {
                let raw = args.next().ok_or("--code-theme 옵션에 테마 이름(예: vs, solarized-light, bw)이 필요합니다.")?;
                code_theme_arg = Some(parse_code_theme(&raw)?);
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
    let mut ctx = BinaryContext::parse(mmap.as_slice())?;
    if let Some(tokens) = compact_arg {
        ctx.compact_tokens = tokens;
    }
    if let Some(ref theme) = code_theme_arg {
        ctx.code_theme = theme.clone();
    }

    let is_tty = unsafe { isatty(0) == 1 };
    if preset_mode
        || (!is_tty
            && patches_arg.is_none()
            && output_arg.is_none()
            && !in_place
            && compact_arg.is_none()
            && code_theme_arg.is_none())
    {
        let mut nodrip_patches: Vec<&'static PatchSpec> =
            PATCH_REGISTRY.iter().filter(|p| p.default_on && p.id != "batch").collect();
        let mut batch_patches: Vec<&'static PatchSpec> =
            PATCH_REGISTRY.iter().filter(|p| p.default_on).collect();
        if compact_arg.is_some() {
            ensure_patch_selected(&mut nodrip_patches, "compact");
            ensure_patch_selected(&mut batch_patches, "compact");
        }
        if code_theme_arg.is_some() {
            ensure_patch_selected(&mut nodrip_patches, "code-theme");
            ensure_patch_selected(&mut batch_patches, "code-theme");
        }
        let jobs = [("agy-nodrip", nodrip_patches), ("agy-batch", batch_patches)];
        // 둘 다 먼저 검사해서 하나만 만들어진 채로 멈추는 일이 없게 한다
        let plans = jobs
            .iter()
            .map(|(name, _)| plan_output(bin_dir, &target_bin, &src_bin, name))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.message(CLI_IN_PLACE_HINT))?;
        for ((_, patches), plan) in jobs.iter().zip(&plans) {
            build_from_plan(&src_bin, &ctx, patches, plan)?;
        }
        return Ok(());
    }

    let (chosen_patches, out_name, do_in_place, final_compact_tokens, final_code_theme) =
        if patches_arg.is_none()
            && output_arg.is_none()
            && !in_place
            && compact_arg.is_none()
            && code_theme_arg.is_none()
        {
            match interactive_wizard(&src_bin, &target_bin, &target_version, &ctx)? {
                Some(result) => result,
                None => {
                    println!("취소되었습니다.");
                    return Ok(());
                }
            }
        } else {
            let mut inline_override = None;
            let mut inline_theme_override = None;
            let mut patches = parse_patch_list(
                patches_arg.as_deref().unwrap_or("all"),
                &mut inline_override,
                &mut inline_theme_override,
            )?;
            let mut resolved_tokens = ctx.compact_tokens;
            if let Some(v) = inline_override {
                resolved_tokens = v;
            }
            if let Some(v) = compact_arg {
                resolved_tokens = v;
                ensure_patch_selected(&mut patches, "compact");
            }
            let mut resolved_theme = ctx.code_theme.clone();
            if let Some(t) = inline_theme_override {
                resolved_theme = t;
            }
            if let Some(t) = code_theme_arg {
                resolved_theme = t;
                ensure_patch_selected(&mut patches, "code-theme");
            }
            let default_out = if patches.iter().any(|p| p.id == "batch") {
                "agy-batch"
            } else {
                "agy-patched"
            };
            let name = output_arg.unwrap_or_else(|| default_out.to_string());
            (patches, name, in_place, resolved_tokens, resolved_theme)
        };
    ctx.compact_tokens = final_compact_tokens;
    ctx.code_theme = final_code_theme.clone();

    if do_in_place {
        if !backup_bin.exists() {
            copy_reflink(&src_bin, &backup_bin)?;
            println!("[+] 원본 백업 저장: {}", backup_bin.display());
        }
        let backup_mmap = MmapFile::open(&backup_bin)?;
        let mut backup_ctx = BinaryContext::parse(backup_mmap.as_slice())?;
        backup_ctx.compact_tokens = final_compact_tokens;
        backup_ctx.code_theme = final_code_theme;
        build_patched_binary(&backup_bin, &backup_ctx, &chosen_patches, &target_bin, None)?;
        println!("[+] 기본 agy 바이너리에 패치 적용 완료: {}", target_bin.display());
        return Ok(());
    }

    let plan = plan_output(bin_dir, &target_bin, &src_bin, &out_name).map_err(|e| e.message(CLI_IN_PLACE_HINT))?;
    build_from_plan(&src_bin, &ctx, &chosen_patches, &plan)
}

fn main() {
    // Rust 런타임은 SIGPIPE 를 무시하도록 바꿔 두므로, `--list | head` 처럼 읽는 쪽이 먼저
    // 닫히면 println! 이 EPIPE 로 패닉한다. 기본 동작으로 되돌려 조용히 종료되게 한다.
    unsafe {
        signal(SIGPIPE, SIG_DFL);
    }
    if let Err(e) = run() {
        eprintln!("[!] 오류: {e}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_token_parser_supports_suffixes_and_validates_range() {
        assert_eq!(parse_compact_tokens("180k"), Ok(180_000));
        assert_eq!(parse_compact_tokens("180_000"), Ok(180_000));
        assert_eq!(parse_compact_tokens("180,000"), Ok(180_000));
        assert_eq!(parse_compact_tokens("1m"), Ok(1_000_000));
        assert_eq!(parse_compact_tokens("32k"), Ok(32_000));

        assert!(parse_compact_tokens("180").is_err());
        assert!(parse_compact_tokens("2m").is_err());
        assert!(parse_compact_tokens("").is_err());
        assert!(parse_compact_tokens("abc").is_err());
    }

    #[test]
    fn resolve_compact_patches_and_repatches_idempotently() {
        let mut buf = vec![0x90u8; 256];
        let ov_start = 16usize;
        let ov_end = 48usize;
        let ov_sig = [0xff, 0xd2, 0x84, 0xc0, 0x75, 0x08, 0x48, 0x8b, 0x44, 0x24];
        buf[ov_start + 4..ov_start + 4 + ov_sig.len()].copy_from_slice(&ov_sig);

        let gc_start = 80usize;
        let gc_end = 200usize;
        let orig = 256_000u32.to_le_bytes();
        // 상한 비교·대입 슬롯: cmp $0x3e800, %edx; mov $0x3e800, %esi; cmovb %edx, %esi
        let limit_off = gc_start + 10;
        buf[limit_off..limit_off + 2].copy_from_slice(&[0x81, 0xfa]);
        buf[limit_off + 2..limit_off + 6].copy_from_slice(&orig);
        buf[limit_off + 6] = 0xbe;
        buf[limit_off + 7..limit_off + 11].copy_from_slice(&orig);
        buf[limit_off + 11..limit_off + 14].copy_from_slice(&[0x0f, 0x42, 0xf2]);

        // 폴백 슬롯
        let fb_off = gc_start + 60;
        buf[fb_off..fb_off + 2].copy_from_slice(&[0x83, 0x7a]);
        buf[fb_off + 2] = 0x14;
        buf[fb_off + 3..fb_off + 9].copy_from_slice(&[0x00, 0x7f, 0x07, 0xc7, 0x40, 0x0c]);
        buf[fb_off + 9..fb_off + 13].copy_from_slice(&orig);

        let apply_edits = |target_buf: &mut [u8], tokens: u32| {
            let mut funcs = HashMap::new();
            funcs.insert("config.applyFeatureProviderCheckpointOverrideConfig", (ov_start, ov_end));
            funcs.insert("utils.GetCheckpointConfig", (gc_start, gc_end));
            let ctx = BinaryContext {
                data: target_buf,
                format: Format::Elf64,
                arch: Arch::X86_64,
                segments: Vec::new(),
                funcs,
                compact_tokens: tokens,
                code_theme: DEFAULT_CODE_THEME.to_string(),
            };
            let edits = resolve_compact(&ctx).expect("합성 바이너리에서 compact 매칭이 성공해야 함");
            assert_eq!(edits.len(), 4);
            for edit in edits {
                target_buf[edit.offset..edit.offset + edit.payload.len()]
                    .copy_from_slice(&edit.payload);
            }
        };

        apply_edits(&mut buf, 180_000);
        assert_eq!(&buf[ov_start + 8..ov_start + 10], &[0x90, 0x90]);
        assert_eq!(read_u32(&buf, limit_off + 2), 180_000);
        assert_eq!(read_u32(&buf, limit_off + 7), 180_000);
        assert_eq!(read_u32(&buf, fb_off + 9), 180_000);

        // 재패치 멱등성 확인 (180k -> 400k)
        apply_edits(&mut buf, 400_000);
        assert_eq!(&buf[ov_start + 8..ov_start + 10], &[0x90, 0x90]);
        assert_eq!(read_u32(&buf, limit_off + 2), 400_000);
        assert_eq!(read_u32(&buf, limit_off + 7), 400_000);
        assert_eq!(read_u32(&buf, fb_off + 9), 400_000);
    }

    #[test]
    fn code_theme_parser_validates_names() {
        assert_eq!(parse_code_theme("vs"), Ok("vs".to_string()));
        assert_eq!(
            parse_code_theme("  Solarized-Light "),
            Ok("solarized-light".to_string())
        );
        assert_eq!(
            parse_code_theme("catppuccin_latte"),
            Ok("catppuccin_latte".to_string())
        );

        assert!(parse_code_theme("").is_err());
        assert!(parse_code_theme("   ").is_err());
        assert!(parse_code_theme("bad name").is_err());
        assert!(parse_code_theme("vs!").is_err());
        assert!(parse_code_theme(&"a".repeat(33)).is_err());
    }

    #[test]
    fn resolve_code_theme_patches_and_repatches_idempotently() {
        let mut buf = vec![0x90u8; 512];
        let mut ro_cursor = 16usize;
        let mut write_tag = |tag: &[u8]| -> usize {
            let off = ro_cursor;
            buf[off..off + tag.len()].copy_from_slice(tag);
            ro_cursor += tag.len() + 8;
            off + 13 // <style name=" 뒤 문자열 시작 오프셋
        };
        let native_off = write_tag(b"<style name=\"native\">");
        let vs_off = write_tag(b"<style name=\"vs\">");
        let sol_off = write_tag(b"<style name=\"solarized-light\">");

        let fn_start = 160usize;
        let fn_end = 300usize;
        let site = fn_start + 12;
        buf[site..site + 2].copy_from_slice(&[0x48, 0xb8]);
        buf[site + 2..site + 10].copy_from_slice(b"terminal");
        buf[site + 10..site + 13].copy_from_slice(&[0x48, 0x39, 0x02]);
        buf[site + 13..site + 19].copy_from_slice(&[0x0f, 0x85, 0x50, 0x00, 0x00, 0x00]);
        let lea_off = site + 19;
        let lea_next = lea_off + 7;
        let disp_native = (native_off as i64 - lea_next as i64) as i32;
        buf[lea_off..lea_off + 3].copy_from_slice(&[0x48, 0x8d, 0x05]);
        buf[lea_off + 3..lea_next].copy_from_slice(&disp_native.to_le_bytes());
        buf[lea_next..lea_next + 8].copy_from_slice(&[0x48, 0x89, 0x84, 0x24, 0x18, 0x16, 0x00, 0x00]);
        let mov_len_off = lea_next + 8;
        buf[mov_len_off..mov_len_off + 8]
            .copy_from_slice(&[0x48, 0xc7, 0x84, 0x24, 0x20, 0x16, 0x00, 0x00]);
        buf[mov_len_off + 8..mov_len_off + 12].copy_from_slice(&6u32.to_le_bytes());

        fn make_ctx<'a>(
            target_buf: &'a [u8],
            theme: &str,
            fn_start: usize,
            fn_end: usize,
        ) -> BinaryContext<'a> {
            let mut funcs = HashMap::new();
            funcs.insert("render.glamourStyleForScheme", (fn_start, fn_end));
            BinaryContext {
                data: target_buf,
                format: Format::Elf64,
                arch: Arch::X86_64,
                segments: Vec::new(),
                funcs,
                compact_tokens: DEFAULT_COMPACT_TOKENS,
                code_theme: theme.to_string(),
            }
        }

        assert_eq!(detect_patched_code_theme(&make_ctx(&buf, "vs", fn_start, fn_end)), None);

        let bad = resolve_code_theme(&make_ctx(&buf, "nonexistent-theme", fn_start, fn_end));
        assert!(bad.is_err());

        let apply = |target_buf: &mut [u8], theme: &str| {
            let edits = {
                let ctx = make_ctx(target_buf, theme, fn_start, fn_end);
                resolve_code_theme(&ctx).expect("합성 바이너리에서 code-theme 매칭이 성공해야 함")
            };
            assert_eq!(edits.len(), 2);
            for edit in edits {
                target_buf[edit.offset..edit.offset + edit.payload.len()]
                    .copy_from_slice(&edit.payload);
            }
        };

        apply(&mut buf, "vs");
        assert_eq!(read_i32(&buf, lea_off + 3), (vs_off as i64 - lea_next as i64) as i32);
        assert_eq!(read_u32(&buf, mov_len_off + 8), 2);
        assert_eq!(
            detect_patched_code_theme(&make_ctx(&buf, "vs", fn_start, fn_end)).as_deref(),
            Some("vs")
        );

        // 재패치 멱등성 확인 (vs -> solarized-light)
        apply(&mut buf, "solarized-light");
        assert_eq!(read_i32(&buf, lea_off + 3), (sol_off as i64 - lea_next as i64) as i32);
        assert_eq!(read_u32(&buf, mov_len_off + 8), 15);
        assert_eq!(
            detect_patched_code_theme(&make_ctx(&buf, "solarized-light", fn_start, fn_end))
                .as_deref(),
            Some("solarized-light")
        );
    }

    fn put_words(buf: &mut [u8], off: usize, insns: &[u32]) {
        buf[off..off + insns.len() * 4].copy_from_slice(&words(insns));
    }

    fn a64_ctx<'a>(buf: &'a [u8], funcs: &[(&'static str, usize, usize)], tokens: u32, theme: &str) -> BinaryContext<'a> {
        BinaryContext {
            data: buf,
            format: Format::MachO64,
            arch: Arch::Arm64,
            segments: Vec::new(),
            funcs: funcs.iter().map(|&(n, s, e)| (n, (s, e))).collect(),
            compact_tokens: tokens,
            code_theme: theme.to_string(),
        }
    }

    fn apply(buf: &mut [u8], edits: Vec<ByteEdit>) {
        for e in edits {
            buf[e.offset..e.offset + e.payload.len()].copy_from_slice(&e.payload);
        }
    }

    #[test]
    fn a64_encoders_round_trip() {
        let pc = 0x1_0000_1234usize;
        let target = 0x1_0903_5678usize;
        let w = a64::adrp(5, pc, target).unwrap();
        assert!(a64::is_adrp(w));
        assert_eq!(a64::rd(w), 5);
        assert_eq!(a64::adrp_target(w, pc), target & !0xfff);
        // 아래 방향 페이지
        let w = a64::adrp(16, target, pc).unwrap();
        assert_eq!(a64::adrp_target(w, target), pc & !0xfff);

        let add = a64::add_imm(5, 5, target & 0xfff);
        assert!(a64::is_add_imm(add));
        assert_eq!(a64::add_imm12(add), 0x678);

        let b = a64::b(0x2000, 0x1000).unwrap();
        assert!(a64::is_b(b));
        assert_eq!(a64::branch26_target(b, 0x2000), 0x1000);
        let bl = a64::bl(0x1000, 0x5000).unwrap();
        assert!(a64::is_bl(bl));
        assert_eq!(a64::branch26_target(bl, 0x1000), 0x5000);
        assert!(a64::b(0, 1 << 28).is_err());

        // 실제 agy 1.5.9 macOS arm64 의 b.gt +16 (0x5400008c)
        assert_eq!(a64::bcond(0x5400_008c), Some(a64::COND_GT));
        assert_eq!(a64::bcond_target(0x5400_008c, 0x100), 0x110);
        assert_eq!(a64_mov32_pair(&words(&[0xd29d_0004, 0xf2a0_0064]), 0), Some((4, 256_000)));
    }

    #[test]
    fn a64_compact_patches_and_repatches_idempotently() {
        // 실제 agy 1.5.9 macOS arm64 명령어 그대로
        let mut buf = vec![0u8; 512];
        let (ov_start, ov_end) = (0usize, 64usize);
        put_words(&mut buf, ov_start + 16, &[0xd63f_00c0, 0x3700_0060, 0xf940_27e0, 0x1400_0012]);
        let (gc_start, gc_end) = (128usize, 384usize);
        let limit = gc_start + 16;
        put_words(&mut buf, limit, &[0xd29d_0004, 0xf2a0_0064, 0x6b04_007f, 0xd29d_0004, 0xf2a0_0064, 0x9a84_3063]);
        let fb = gc_start + 128;
        put_words(&mut buf, fb - 8, &[0x7100_007f, 0x5400_008c, 0xd29d_0003, 0xf2a0_0063, 0xb900_0c03]);
        let funcs = [
            ("config.applyFeatureProviderCheckpointOverrideConfig", ov_start, ov_end),
            ("utils.GetCheckpointConfig", gc_start, gc_end),
        ];

        assert_eq!(detect_patched_compact_tokens(&a64_ctx(&buf, &funcs, 0, "vs")), None);
        for tokens in [180_000u32, 400_000, 32_000] {
            let edits = resolve_compact(&a64_ctx(&buf, &funcs, tokens, "vs")).expect("ARM64 compact 매칭");
            assert_eq!(edits.len(), 4);
            apply(&mut buf, edits);
            assert_eq!(word(&buf, ov_start + 20), a64::NOP);
            assert_eq!(a64_mov32_pair(&buf, limit), Some((4, tokens)));
            assert_eq!(a64_mov32_pair(&buf, limit + 12), Some((4, tokens)));
            assert_eq!(a64_mov32_pair(&buf, fb), Some((3, tokens)));
            assert_eq!(detect_patched_compact_tokens(&a64_ctx(&buf, &funcs, 0, "vs")), Some(tokens));
        }
    }

    #[test]
    fn a64_code_theme_patches_and_repatches_idempotently() {
        let mut buf = vec![0u8; 0x3000];
        let mut put_tag = |off: usize, name: &str| {
            let tag = format!("<style name=\"{name}\">");
            buf[off..off + tag.len()].copy_from_slice(tag.as_bytes());
            off + 13
        };
        let native = put_tag(0x1800, "native");
        let vs = put_tag(0x1900, "vs");
        let sol = put_tag(0x2a10, "solarized-light");

        // 실제 agy 1.5.9 macOS arm64 의 두 번째 "terminal" 비교 + "native" 대입
        let (fs, fe) = (0x100usize, 0x200usize);
        let site = fs + 0x20;
        let adrp = a64::adrp(0, site + 24, native).unwrap();
        let add = a64::add_imm(0, 0, native & 0xfff);
        put_words(
            &mut buf,
            site,
            &[0xd28c_ae81, 0xf2ad_ae41, 0xf2cd_cd21, 0xf2ed_8c21, 0xeb01_001f, 0x5400_07e1,
              adrp, add, 0xb27f_07e1, 0x913f_fffb, 0x9118_c77b, 0xa900_0760],
        );
        let funcs = [("render.glamourStyleForScheme", fs, fe)];

        assert_eq!(detect_patched_code_theme(&a64_ctx(&buf, &funcs, 0, "vs")), None);
        assert!(resolve_code_theme(&a64_ctx(&buf, &funcs, 0, "nonexistent-theme")).is_err());
        for (theme, off) in [("vs", vs), ("solarized-light", sol)] {
            let edits = resolve_code_theme(&a64_ctx(&buf, &funcs, 0, theme)).expect("ARM64 code-theme 매칭");
            apply(&mut buf, edits);
            let w = word(&buf, site + 24);
            assert_eq!(a64::adrp_target(w, site + 24) + a64::add_imm12(word(&buf, site + 28)), off);
            assert_eq!(word(&buf, site + 32), a64::movz(1, theme.len() as u32));
            assert_eq!(detect_patched_code_theme(&a64_ctx(&buf, &funcs, 0, theme)).as_deref(), Some(theme));
        }
    }
}
