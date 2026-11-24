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

/// PIE ELF 에서는 pclntab 의 textStart 가 0 으로 남고(읽기 전용이라 재배치되지 않음),
/// 실제 Go 코드 시작은 runtime.firstmoduledata.text 에 R_*_RELATIVE 재배치의 addend 로만 들어 있다.
/// moduledata 첫 필드(pcHeader 포인터)가 pclntab 을 가리키는 재배치로 moduledata 를 찾고,
/// text 필드(+176, Go 1.16+ 레이아웃)의 재배치 addend 를 읽는다.
/// Linux ARM64 는 .text 앞에 C 런타임 코드가 있어 이 값 없이는 모든 함수 위치가 어긋난다.
fn elf_go_text_va(data: &[u8], segments: &[(usize, usize, usize)], pcln_off: usize) -> Option<usize> {
    const MODULEDATA_TEXT: u64 = 176;
    let pcln_va = segments
        .iter()
        .find(|&&(off, _, size)| pcln_off >= off && pcln_off - off < size)
        .map(|&(off, va, _)| (va + (pcln_off - off)) as u64)?;
    let e_shoff = read_u64(data, 0x28) as usize;
    let e_shentsize = read_u16(data, 0x3a) as usize;
    let e_shnum = read_u16(data, 0x3c) as usize;
    let relas: Vec<(usize, usize)> = (0..e_shnum)
        .map(|i| e_shoff + i * e_shentsize)
        .filter(|&b| b + 40 <= data.len() && read_u32(data, b + 4) == 4) // SHT_RELA
        .map(|b| (read_u64(data, b + 24) as usize, read_u64(data, b + 32) as usize))
        .filter(|&(off, size)| off + size <= data.len())
        .collect();
    let is_relative = |info: u64| matches!(info & 0xffff_ffff, 8 | 1027); // R_X86_64_RELATIVE, R_AARCH64_RELATIVE
    let find = |pred: &dyn Fn(u64, u64) -> bool| -> Option<(u64, u64)> {
        relas.iter().find_map(|&(off, size)| {
            (0..size / 24).map(|k| off + k * 24).find_map(|e| {
                let (r_off, info, addend) = (read_u64(data, e), read_u64(data, e + 8), read_u64(data, e + 16));
                (is_relative(info) && pred(r_off, addend)).then_some((r_off, addend))
            })
        })
    };
    let (moduledata, _) = find(&|_, addend| addend == pcln_va)?;
    let (_, text) = find(&|r_off, _| r_off == moduledata + MODULEDATA_TEXT)?;
    Some(text as usize)
}

/// Go 심볼 전체 이름에서 제네릭 인자(`[...]`) 안의 `/`에 흔들리지 않고 `pkg.Func` 접미사만 떼어낸다.
fn short_go_symbol(full_name: &str) -> &str {
    let head = full_name.split('[').next().unwrap_or(full_name);
    match head.rfind('/') {
        Some(pos) => &full_name[pos + 1..],
        None => full_name,
    }
}

/// Go 1.20+ `.gopclntab` 메타데이터 오프셋.
/// `ftab` 이진 탐색으로 임의 `CALL`/`BL` 목적지의 심볼을 O(log nfunc)으로 역조회하고,
/// 함수 이름이 바뀐 릴리즈에서는 `pcfile` -> `cutab` -> `filetab`으로 원본 `.go` 파일 경로를 역추적한다.
#[derive(Clone, Copy)]
struct PclnTab {
    nfunc: usize,
    go_text_off: usize,
    funcname_base: usize,
    cu_base: usize,
    filetab_base: usize,
    pctab_base: usize,
    ftab_base: usize,
}

impl PclnTab {
    fn func_name_at<'a>(&self, data: &'a [u8], idx: usize) -> Option<&'a str> {
        if idx >= self.nfunc {
            return None;
        }
        let ftab_entry = self.ftab_base.checked_add(idx.checked_mul(8)?)?;
        if ftab_entry + 8 > data.len() {
            return None;
        }
        let func_off = read_u32(data, ftab_entry + 4) as usize;
        let meta = self.ftab_base.checked_add(func_off)?;
        if meta + 8 > data.len() {
            return None;
        }
        let name_off = usize::try_from(read_i32(data, meta + 4)).ok()?;
        let name_start = self.funcname_base.checked_add(name_off)?;
        let s = data.get(name_start..)?;
        let len = s.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&s[..len]).ok()
    }

    fn func_range(&self, data: &[u8], idx: usize) -> Option<(usize, usize)> {
        if idx >= self.nfunc {
            return None;
        }
        let ftab_entry = self.ftab_base.checked_add(idx.checked_mul(8)?)?;
        if ftab_entry + 12 > data.len() {
            return None;
        }
        let entry_off = read_u32(data, ftab_entry) as usize;
        let next_entry_off = read_u32(data, ftab_entry + 8) as usize;
        let start = self.go_text_off.checked_add(entry_off)?;
        let end = self.go_text_off.checked_add(next_entry_off)?;
        (start <= end && end <= data.len()).then_some((start, end))
    }

    /// 함수 진입점 파일 오프셋에서 Go 심볼 전체 이름을 O(log nfunc) 이진 탐색으로 찾는다.
    fn func_at_entry<'a>(&self, data: &'a [u8], target_file_off: usize) -> Option<&'a str> {
        let rel = u32::try_from(target_file_off.checked_sub(self.go_text_off)?).ok()?;
        let (mut lo, mut hi) = (0usize, self.nfunc);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let pos = self.ftab_base.checked_add(mid * 8)?;
            if pos + 4 > data.len() {
                return None;
            }
            if read_u32(data, pos) < rel {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo < self.nfunc {
            let pos = self.ftab_base.checked_add(lo * 8)?;
            if pos + 4 <= data.len() && read_u32(data, pos) == rel {
                return self.func_name_at(data, lo);
            }
        }
        None
    }

    fn func_first_file_off(&self, data: &[u8], idx: usize, max_cu_idx: usize) -> Option<u32> {
        if idx >= self.nfunc {
            return None;
        }
        let ftab_entry = self.ftab_base.checked_add(idx.checked_mul(8)?)?;
        if ftab_entry + 8 > data.len() {
            return None;
        }
        let func_off = read_u32(data, ftab_entry + 4) as usize;
        let meta = self.ftab_base.checked_add(func_off)?;
        if meta + 36 > data.len() {
            return None;
        }
        let pcfile = read_u32(data, meta + 20);
        let cu_offset = read_u32(data, meta + 32);
        if pcfile == 0 || (cu_offset as usize) > max_cu_idx {
            return None;
        }
        let mut pos = self.pctab_base.checked_add(pcfile as usize)?;
        let (mut uvdelta, mut shift) = (0u32, 0u32);
        loop {
            let b = *data.get(pos)?;
            pos += 1;
            uvdelta |= u32::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 35 {
                return None;
            }
        }
        let sdelta = -((uvdelta & 1) as i32) ^ ((uvdelta >> 1) as i32);
        let fno = u32::try_from(-1i32 + sdelta).ok()?;
        let cu_idx = cu_offset.checked_add(fno)? as usize;
        if cu_idx > max_cu_idx {
            return None;
        }
        let cutab_pos = self.cu_base.checked_add(cu_idx.checked_mul(4)?)?;
        if cutab_pos + 4 > data.len() {
            return None;
        }
        let file_off = read_u32(data, cutab_pos);
        (file_off != u32::MAX).then_some(file_off)
    }

    /// `_func`의 `pcfile`(pctab zigzag varint) + `cuOffset`(cutab) + `filetab`을 디코드해
    /// 함수 진입점이 속한 원본 `.go` 소스 파일 경로를 돌려준다.
    #[cfg(test)]
    fn func_first_file<'a>(&self, data: &'a [u8], idx: usize) -> Option<&'a str> {
        let file_off = self.func_first_file_off(data, idx, usize::MAX)?;
        let fstart = self.filetab_base.checked_add(file_off as usize)?;
        let s = data.get(fstart..)?;
        let len = s.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&s[..len]).ok()
    }

    fn funcs_in_file(&self, data: &[u8], file_suffix: &str) -> Vec<(usize, usize)> {
        let filetab_end = [self.funcname_base, self.cu_base, self.pctab_base, self.ftab_base, data.len()]
            .into_iter()
            .filter(|&b| b > self.filetab_base && b <= data.len())
            .min()
            .unwrap_or(data.len());
        let Some(ft_slice) = data.get(self.filetab_base..filetab_end) else {
            return Vec::new();
        };
        let mut needle = Vec::with_capacity(file_suffix.len() + 1);
        needle.extend_from_slice(file_suffix.as_bytes());
        needle.push(0);

        let mut target_offs = Vec::new();
        for rel_hit in find_all(ft_slice, &needle) {
            if rel_hit == 0 || matches!(ft_slice[rel_hit - 1], 0 | b'/') {
                let mut start = rel_hit;
                while start > 0 && ft_slice[start - 1] != 0 {
                    start -= 1;
                }
                if let Ok(off32) = u32::try_from(start) {
                    target_offs.push(off32);
                }
            }
        }
        if target_offs.is_empty() {
            return Vec::new();
        }

        let cutab_end = [self.funcname_base, self.filetab_base, self.pctab_base, self.ftab_base, data.len()]
            .into_iter()
            .filter(|&b| b > self.cu_base && b <= data.len())
            .min()
            .unwrap_or(data.len());
        let max_cu_idx = data
            .get(self.cu_base..cutab_end)
            .map(|cu| {
                (0..cu.len() / 4)
                    .rfind(|&i| target_offs.contains(&read_u32(cu, i * 4)))
                    .unwrap_or(usize::MAX)
            })
            .unwrap_or(usize::MAX);

        (0..self.nfunc)
            .filter(|&i| {
                self.func_first_file_off(data, i, max_cu_idx)
                    .is_some_and(|fo| target_offs.contains(&fo))
            })
            .filter_map(|i| self.func_range(data, i))
            .collect()
    }
}

struct BinaryContext<'a> {
    data: &'a [u8],
    format: Format,
    arch: Arch,
    segments: Vec<(usize, usize, usize)>, // (file_off, va, file_size)
    funcs: HashMap<&'a str, (usize, usize)>,
    pcln: Option<PclnTab>,
    compact_tokens: u32,
    code_theme: String,
    /// TIERS 순서 (pro, flash, flash_lite)
    tier_models: [String; 3],
    /// Go 코드가 든 코드 섹션(ELF `.text`, Mach-O `__text`)의 파일 범위 [시작, 끝)
    text_section: Option<(usize, usize)>,
    /// 이번 빌드에 선택된 패치 ID 목록 (`patch-info` 배너 요약 생성용)
    selected_patches: Vec<&'static str>,
}

impl<'a> BinaryContext<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, String> {
        let mut segments = Vec::new();
        let (format, arch, text_va, text_off, text_size) = if &data[..4] == b"\x7fELF" {
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
            let mut t_size = 0usize;
            for i in 0..e_shnum {
                let (sh_name, sh_addr, sh_off, sh_size) = shdr(i);
                let s = &shstr[sh_name as usize..];
                let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
                if &s[..end] == b".text" {
                    t_va = sh_addr as usize;
                    t_off = sh_off as usize;
                    t_size = sh_size as usize;
                    break;
                }
            }
            if t_off == 0 {
                return Err("ELF .text 섹션을 찾을 수 없습니다.".into());
            }
            (Format::Elf64, arch, t_va, t_off, t_size)
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
            let mut t_size = 0usize;
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
                            t_size = read_u64(data, sect_off + 40) as usize;
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
            (Format::MachO64, arch, t_va, t_off, t_size)
        } else {
            return Err("지원하지 않는 바이너리 포맷입니다 (ELF64 또는 Mach-O 64 필요).".into());
        };

        let pcln_magic: &[u8] = match arch {
            Arch::X86_64 => b"\xf1\xff\xff\xff\x00\x00\x01\x08",
            Arch::Arm64 => b"\xf1\xff\xff\xff\x00\x00\x04\x08",
        };
        let pcln_off = find_subslice(data, pcln_magic)
            .ok_or_else(|| "Go .gopclntab 헤더를 찾을 수 없습니다.".to_string())?;
        if pcln_off + 72 > data.len() {
            return Err("Go .gopclntab 헤더가 손상되었습니다.".into());
        }

        let nfunc = read_u64(data, pcln_off + 8) as usize;
        let text_start = read_u64(data, pcln_off + 24) as usize;
        let funcname_off = read_u64(data, pcln_off + 32) as usize;
        let cu_off = read_u64(data, pcln_off + 40) as usize;
        let filetab_off = read_u64(data, pcln_off + 48) as usize;
        let pctab_off = read_u64(data, pcln_off + 56) as usize;
        let ftab_off = read_u64(data, pcln_off + 64) as usize;

        let pie_text_off = (text_start == 0 && format == Format::Elf64)
            .then(|| elf_go_text_va(data, &segments, pcln_off))
            .flatten()
            .and_then(|va| {
                segments
                    .iter()
                    .find(|&&(_, s_va, size)| va >= s_va && va - s_va < size)
                    .map(|&(file_off, s_va, _)| file_off + (va - s_va))
            });

        let go_text_off = if text_start != 0 {
            text_off + (text_start - text_va)
        } else if let Some(off) = pie_text_off {
            off
        } else if format == Format::Elf64 && arch == Arch::X86_64 {
            // Linux ELF64 CGO/PIE: .text 앞쪽 glibc CRT 패딩(0xcc) 직후 첫 Go 함수 프롤로그 탐색
            let window = &data[text_off..(text_off + 0x1000).min(data.len())];
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

        let pcln = PclnTab {
            nfunc,
            go_text_off,
            funcname_base: pcln_off + funcname_off,
            cu_base: pcln_off + cu_off,
            filetab_base: pcln_off + filetab_off,
            pctab_base: pcln_off + pctab_off,
            ftab_base: pcln_off + ftab_off,
        };

        let target_suffixes = [
            "store.cutAtRuneBoundary",
            "render.renderPlannerBody",
            "render.glamourStyleForScheme",
            "render.glamourStyle", // 1.5.14+ 에서 glamourStyleForScheme 이 이 이름으로 바뀜
            "parser.ScanDelimiter",
            "extension.(*strikethroughParser).Parse",
            "utils.GetCheckpointConfig",
            "config.applyFeatureProviderCheckpointOverrideConfig",
            "modelutils.modelIDForTier",
            "render.BuildHeader",
            "render.BannerWithInfo",
            "runtime.concatstring2",
            "runtime.concatstring3",
        ];

        let mut funcs = HashMap::with_capacity(target_suffixes.len());
        for i in 0..nfunc {
            if let Some(full_name) = pcln.func_name_at(data, i) {
                let short = short_go_symbol(full_name);
                if let Some(&target) = target_suffixes.iter().find(|&&t| t == short) {
                    if let Some(range) = pcln.func_range(data, i) {
                        funcs.insert(target, range);
                        if funcs.len() == target_suffixes.len() {
                            break;
                        }
                    }
                }
            }
        }

        Ok(Self {
            data,
            format,
            arch,
            segments,
            funcs,
            pcln: Some(pcln),
            compact_tokens: DEFAULT_COMPACT_TOKENS,
            code_theme: DEFAULT_CODE_THEME.to_string(),
            tier_models: default_tier_models(),
            text_section: Some((text_off, (text_off + text_size).min(data.len()))),
            selected_patches: Vec::new(),
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

    /// x86_64 `CALL rel32` (`0xe8`) 목적지의 파일 오프셋
    fn x86_call_target_off(&self, call_off: usize) -> Option<usize> {
        if self.data.get(call_off) != Some(&0xe8) || call_off + 5 > self.data.len() {
            return None;
        }
        let pc_va = self.off_to_va(call_off + 5)? as i64;
        let target_va = usize::try_from(pc_va + read_i32(self.data, call_off + 1) as i64).ok()?;
        self.va_to_off(target_va)
    }

    /// ARM64 `BL imm26` 목적지의 파일 오프셋
    fn a64_bl_target_off(&self, bl_off: usize) -> Option<usize> {
        if bl_off + 4 > self.data.len() {
            return None;
        }
        let w = word(self.data, bl_off);
        if !a64::is_bl(w) {
            return None;
        }
        let pc_va = self.off_to_va(bl_off)?;
        self.va_to_off(a64::branch26_target(w, pc_va))
    }

    /// 함수 진입점 파일 오프셋에 대응하는 짧은 Go 심볼(`pkg.Func`).
    /// `.gopclntab`이 있으면 `ftab` 이진 탐색으로 전체 심볼을 조회하고, 없는 합성 테스트에서는 `funcs`에서 찾는다.
    fn symbol_at_entry(&self, target_off: usize) -> Option<&'a str> {
        self.pcln
            .and_then(|p| p.func_at_entry(self.data, target_off))
            .map(short_go_symbol)
            .or_else(|| {
                self.funcs
                    .iter()
                    .find_map(|(&name, &(s, _))| (s == target_off).then_some(name))
            })
    }

    /// 현재 아키텍처의 직접 함수 호출(`CALL` / `BL`)이 가리키는 대상 Go 심볼 이름
    fn call_target_symbol(&self, insn_off: usize) -> Option<&'a str> {
        let target = match self.arch {
            Arch::X86_64 => self.x86_call_target_off(insn_off)?,
            Arch::Arm64 => self.a64_bl_target_off(insn_off)?,
        };
        self.symbol_at_entry(target)
    }

    /// x86_64 `LEA disp32(%rip), r64`가 가리키는 (레지스터 번호 0..15, 대상 파일 오프셋)
    fn x86_lea_target_off(&self, lea_off: usize) -> Option<(u8, usize)> {
        let w = self.data.get(lea_off..lea_off + 7)?;
        if !matches!(w[0], 0x48 | 0x4c) || w[1] != 0x8d || (w[2] & 0xc7) != 0x05 {
            return None;
        }
        let reg = ((w[0] & 0x04) << 1) | ((w[2] >> 3) & 7);
        let pc_va = self.off_to_va(lea_off + 7)? as i64;
        let target_va = usize::try_from(pc_va + read_i32(self.data, lea_off + 3) as i64).ok()?;
        Some((reg, self.va_to_off(target_va)?))
    }

    /// ARM64 `ADRP xP, page; ADD xP, xP, #imm12` 쌍이 가리키는 (레지스터 번호 0..31, 대상 파일 오프셋)
    fn a64_adrp_add_target_off(&self, adrp_off: usize) -> Option<(u32, usize)> {
        if adrp_off + 8 > self.data.len() {
            return None;
        }
        let (w0, w1) = (word(self.data, adrp_off), word(self.data, adrp_off + 4));
        if !a64::is_adrp(w0) || !a64::is_add_imm(w1) {
            return None;
        }
        let p = a64::rd(w0);
        if a64::rd(w1) != p || a64::add_rn(w1) != p {
            return None;
        }
        let pc_va = self.off_to_va(adrp_off)?;
        let target_va = a64::adrp_target(w0, pc_va) + a64::add_imm12(w1);
        Some((p, self.va_to_off(target_va)?))
    }

    /// 등록된 후보 심볼에서 먼저 매칭을 시도하고, 함수 이름이 바뀐 미래 버전에서는
    /// `.gopclntab`의 `filetab`에서 같은 원본 `.go` 소스 파일에 속한 함수들로 자동 폴백한다.
    fn resolve_in_funcs<T, F>(
        &self,
        symbols: &[&str],
        file_suffix: &str,
        label: &str,
        mut scan: F,
    ) -> Result<T, String>
    where
        F: FnMut(usize, usize) -> Vec<T>,
    {
        let mut named_ranges = Vec::new();
        for &sym in symbols {
            if let Some(&range) = self.funcs.get(sym) {
                if !named_ranges.contains(&range) {
                    named_ranges.push(range);
                }
            }
        }
        if !named_ranges.is_empty() {
            let mut matches: Vec<T> = named_ranges.iter().flat_map(|&(s, e)| scan(s, e)).collect();
            if matches.len() == 1 {
                return Ok(matches.pop().unwrap());
            }
            if matches.len() > 1 {
                return Err(format!("{label} 패턴 매칭 실패 (매칭 수: {})", matches.len()));
            }
        }
        if let Some(pcln) = self.pcln {
            let file_ranges = pcln.funcs_in_file(self.data, file_suffix);
            if !file_ranges.is_empty() {
                let mut matches: Vec<T> = file_ranges.into_iter().flat_map(|(s, e)| scan(s, e)).collect();
                if matches.len() == 1 {
                    return Ok(matches.pop().unwrap());
                }
                return Err(format!("{label} 패턴 매칭 실패 (매칭 수: {})", matches.len()));
            }
        }
        if named_ranges.is_empty() {
            return Err(format!(
                "심볼 테이블에서 함수를 찾을 수 없습니다: {}",
                symbols.join(" / ")
            ));
        }
        Err(format!("{label} 패턴 매칭 실패 (매칭 수: 0)"))
    }
}

// --- 패치 명세 및 아키텍처별(x86_64 / ARM64) 리졸버 ---

#[derive(Clone, Debug, PartialEq, Eq)]
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

// --- ARM64 명령어 인코딩/디코딩 (code-theme / compact / banner / patch-info 공용) ---

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
    pub const COND_EQ: u32 = 0;
    pub const COND_NE: u32 = 1;
    pub const COND_LO: u32 = 3;
    pub const COND_LS: u32 = 9;
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

/// x86_64 분기/경계 정렬용 NOP 패딩(`0x90`, `66 90`, `0f 1f ...`)을 건너뛴다.
fn skip_x86_nops(body: &[u8], mut pos: usize) -> usize {
    loop {
        let rest = &body[pos..];
        let step = if rest.first() == Some(&0x90) {
            1
        } else if rest.starts_with(&[0x66, 0x90]) {
            2
        } else if rest.starts_with(&[0x0f, 0x1f, 0x00]) {
            3
        } else if rest.starts_with(&[0x0f, 0x1f, 0x40, 0x00]) {
            4
        } else if rest.starts_with(&[0x0f, 0x1f, 0x44, 0x00, 0x00]) {
            5
        } else if rest.starts_with(&[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00]) {
            6
        } else if rest.starts_with(&[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00]) {
            7
        } else if rest.starts_with(&[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]) {
            8
        } else if rest.starts_with(&[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]) {
            9
        } else {
            break;
        };
        pos += step;
    }
    pos
}

/// x86_64 `cmp $imm8, r32/r64` -> `(명령 길이, imm8)`
fn x86_cmp_imm8(b: &[u8]) -> Option<(usize, u8)> {
    match b {
        [0x83, m, imm, ..] if (0xf8..=0xff).contains(m) => Some((3, *imm)),
        [0x41 | 0x48 | 0x49, 0x83, m, imm, ..] if (0xf8..=0xff).contains(m) => Some((4, *imm)),
        _ => None,
    }
}

/// x86_64 조건 분기(`70..7f rel8` 또는 `0f 80..8f rel32`) -> `(조건 코드 0..15, 다음 오프셋, 목적지 오프셋)`
fn x86_jcc_target(body: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    let rest = body.get(pos..)?;
    if let &[op @ 0x70..=0x7f, disp, ..] = rest {
        let next = pos + 2;
        let target = usize::try_from(next as isize + (disp as i8 as isize)).ok()?;
        Some((op - 0x70, next, target))
    } else if rest.len() >= 6 && rest[0] == 0x0f && (0x80..=0x8f).contains(&rest[1]) {
        let next = pos + 6;
        let target = usize::try_from(next as isize + (read_i32(body, pos + 2) as isize)).ok()?;
        Some((rest[1] - 0x80, next, target))
    } else {
        None
    }
}

/// x86_64 `mov r64, [rsp + disp8|disp32]` -> `(명령 길이, 소스 레지스터 0..15, 스택 변위)`
fn x86_rsp_store_info(b: &[u8]) -> Option<(usize, u8, i32)> {
    match b {
        [rex @ (0x48 | 0x4c), 0x89, m, 0x24, d, ..] if m & 0xc7 == 0x44 => {
            Some((5, ((*rex & 4) << 1) | ((m >> 3) & 7), *d as i8 as i32))
        }
        [rex @ (0x48 | 0x4c), 0x89, m, 0x24, ..] if b.len() >= 8 && m & 0xc7 == 0x84 => {
            Some((8, ((*rex & 4) << 1) | ((m >> 3) & 7), read_i32(b, 4)))
        }
        _ => None,
    }
}

/// x86_64 `movq $imm32, [rsp + disp8|disp32]` -> `(명령 길이, 스택 변위, imm32 상대 오프셋, imm32 값)`
fn x86_rsp_imm_store_info(b: &[u8]) -> Option<(usize, i32, usize, u32)> {
    match b {
        [0x48, 0xc7, 0x44, 0x24, d, ..] if b.len() >= 9 => {
            Some((9, *d as i8 as i32, 5, read_u32(b, 5)))
        }
        [0x48, 0xc7, 0x84, 0x24, ..] if b.len() >= 12 => {
            Some((12, read_i32(b, 4), 8, read_u32(b, 8)))
        }
        _ => None,
    }
}

/// `mov r64, [rsp+disp8|disp32]` 이면 그 길이
fn x86_rsp_load_len(b: &[u8]) -> Option<usize> {
    match b {
        [0x48 | 0x4c, 0x8b, m, 0x24, ..] if m & 0xc7 == 0x44 => Some(5),
        [0x48 | 0x4c, 0x8b, m, 0x24, ..] if b.len() >= 8 && m & 0xc7 == 0x84 => Some(8),
        _ => None,
    }
}

const X86_CUT_ORIG: &[u8] = &[0x55, 0x48, 0x89, 0xe5];
const X86_CUT_NEW: &[u8] = &[0x48, 0x89, 0xd8, 0xc3];

const ARM64_CUT_ORIG: &[u8] = &[0x90, 0x0b, 0x40, 0xf9, 0xff, 0x63, 0x30, 0xeb];
const ARM64_CUT_NEW: &[u8] = &[0xe0, 0x03, 0x01, 0xaa, 0xc0, 0x03, 0x5f, 0xd6]; // mov x0, x1; ret

fn is_valid_x86_cut_prologue(b: &[u8]) -> bool {
    b.starts_with(X86_CUT_ORIG)
        || b.starts_with(&[0x49, 0x3b, 0x66, 0x10]) // cmp 0x10(%r14), %rsp
        || matches!(b, [0x4c, 0x8d, 0x64 | 0xa4, 0x24, ..]) // lea disp(%rsp), %r12 (스택 가드)
        || b.starts_with(&[0x48, 0x39, 0xcb]) // 프레임 없는 리프: cmp %rcx, %rbx
}

fn is_valid_a64_cut_prologue(b: &[u8]) -> bool {
    if b.len() < 8 {
        return false;
    }
    let w0 = word(b, 0);
    b.starts_with(ARM64_CUT_ORIG)
        || (w0 & 0xffc0_03ff) == 0xd100_03ff // sub sp, sp, #imm
        || (w0 & 0xffc0_03ff) == 0xd100_03f0 // sub x16, sp, #imm (큰 프레임 스택 가드)
        || (w0 & 0xffc0_7fff) == 0xa980_7bfd // stp x29, x30, [sp, #-N]!
        || w0 == 0xeb02_003f // 프레임 없는 리프: cmp x1, x2
}

/// Go 표준 `unicode/utf8.first` 256바이트 테이블(0x00..0x7f = 0xf0, 0x80..0xc1 = 0xf1) 여부 확인
fn is_utf8_first_table(data: &[u8], off: usize) -> bool {
    let Some(tbl) = data.get(off..off + 194) else {
        return false;
    };
    tbl[..128].iter().all(|&b| b == 0xf0) && tbl[128..194].iter().all(|&b| b == 0xf1)
}

fn find_cut_func(ctx: &BinaryContext) -> Result<(usize, usize), String> {
    if let Some(&range) = ctx.funcs.get("store.cutAtRuneBoundary") {
        return Ok(range);
    }
    if let Some(pcln) = ctx.pcln {
        let mut hits = Vec::new();
        for (s, e) in pcln.funcs_in_file(ctx.data, "cli/store/text_drip.go") {
            let body = &ctx.data[s..e];
            let matched = match ctx.arch {
                Arch::X86_64 => {
                    body.starts_with(X86_CUT_NEW)
                        || (0..body.len().saturating_sub(7)).any(|p| {
                            ctx.x86_lea_target_off(s + p)
                                .is_some_and(|(_, toff)| is_utf8_first_table(ctx.data, toff))
                                || ctx
                                    .call_target_symbol(s + p)
                                    .is_some_and(|sym| sym.starts_with("utf8."))
                        })
                }
                Arch::Arm64 => {
                    body.starts_with(ARM64_CUT_NEW)
                        || (0..body.len().saturating_sub(8)).step_by(4).any(|p| {
                            ctx.a64_adrp_add_target_off(s + p)
                                .is_some_and(|(_, toff)| is_utf8_first_table(ctx.data, toff))
                                || ctx
                                    .call_target_symbol(s + p)
                                    .is_some_and(|sym| sym.starts_with("utf8."))
                        })
                }
            };
            if matched {
                hits.push((s, e));
            }
        }
        if hits.len() == 1 {
            return Ok(hits[0]);
        }
        if hits.len() > 1 {
            return Err(format!("cutAtRuneBoundary 폴백 매칭 모호함 (매칭 수: {})", hits.len()));
        }
    }
    Err("심볼 테이블에서 함수를 찾을 수 없습니다: store.cutAtRuneBoundary".to_string())
}

fn is_unpatched_cut(ctx: &BinaryContext) -> Result<bool, String> {
    let (start, end) = find_cut_func(ctx)?;
    let body = &ctx.data[start..end];
    Ok(match ctx.arch {
        Arch::X86_64 => !body.starts_with(X86_CUT_NEW) && is_valid_x86_cut_prologue(body),
        Arch::Arm64 => !body.starts_with(ARM64_CUT_NEW) && is_valid_a64_cut_prologue(body),
    })
}

fn resolve_nodrip(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    let (start, end) = find_cut_func(ctx)?;
    let body = &ctx.data[start..end];
    match ctx.arch {
        Arch::X86_64 => {
            if body.len() < 4 || (!body.starts_with(X86_CUT_NEW) && !is_valid_x86_cut_prologue(body)) {
                return Err(format!("cutAtRuneBoundary x86_64 프롤로그 불일치 (@0x{start:x})"));
            }
            Ok(vec![ByteEdit {
                offset: start,
                payload: X86_CUT_NEW.to_vec(),
            }])
        }
        Arch::Arm64 => {
            if body.len() < 8 || (!body.starts_with(ARM64_CUT_NEW) && !is_valid_a64_cut_prologue(body)) {
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
    ctx.resolve_in_funcs(
        &["render.renderPlannerBody"],
        "cli/render/planner_body.go",
        "renderPlannerBody 분기",
        |start, end| {
            let body = &ctx.data[start..end];
            let mut edits = Vec::new();
            match ctx.arch {
                Arch::X86_64 => {
                    for i in 0..body.len().saturating_sub(14) {
                        let Some((cmp0_len, 1)) = x86_cmp_imm8(&body[i..]) else {
                            continue;
                        };
                        let jbe_pos = skip_x86_nops(body, i + cmp0_len);
                        let Some((6, mut next, stream_target)) = x86_jcc_target(body, jbe_pos) else {
                            continue;
                        };
                        if stream_target <= next || stream_target + 8 > body.len() {
                            continue;
                        }
                        let mut mid_count = 0usize;
                        loop {
                            let cur = skip_x86_nops(body, next);
                            let Some((cmp_len, imm)) = x86_cmp_imm8(body.get(cur..).unwrap_or(&[])) else {
                                break;
                            };
                            if imm >= 0x40 {
                                break;
                            }
                            let jcc_pos = skip_x86_nops(body, cur + cmp_len);
                            let Some((cc, jcc_next, target)) = x86_jcc_target(body, jcc_pos) else {
                                break;
                            };
                            if matches!(cc, 4 | 6) && target == stream_target {
                                mid_count += 1;
                                next = jcc_next;
                                continue;
                            }
                            if cc == 5
                                && mid_count >= 1
                                && (stream_target == jcc_next || stream_target == skip_x86_nops(body, jcc_next))
                            {
                                let candidate = vec![ByteEdit {
                                    offset: start + stream_target,
                                    payload: vec![0x31, 0xc0, 0x31, 0xdb, 0x31, 0xc9, 0xc9, 0xc3],
                                }];
                                if !edits.contains(&candidate) {
                                    edits.push(candidate);
                                }
                            }
                            break;
                        }
                    }
                }
                Arch::Arm64 => {
                    let is_cmp_imm = |w: u32| (w & 0xffc0_001f) == 0x7100_001f;
                    let cmp_imm = |w: u32| (w >> 10) & 0xfff;
                    for off in (0..body.len().saturating_sub(24)).step_by(4) {
                        let i0 = read_u32(body, off);
                        let i1 = read_u32(body, off + 4);
                        if !is_cmp_imm(i0) || cmp_imm(i0) != 1 || a64::bcond(i1) != Some(a64::COND_LS) {
                            continue;
                        }
                        let stream_rel = a64::bcond_target(i1, off + 4);
                        if stream_rel <= off + 8 || stream_rel + 12 > body.len() {
                            continue;
                        }
                        let mut cur = off + 8;
                        let mut mid_count = 0usize;
                        while cur + 8 <= stream_rel {
                            let cw = read_u32(body, cur);
                            if cw == a64::NOP {
                                cur += 4;
                                continue;
                            }
                            let bw = read_u32(body, cur + 4);
                            if !is_cmp_imm(cw) || cmp_imm(cw) >= 0x40 {
                                break;
                            }
                            match a64::bcond(bw) {
                                Some(a64::COND_EQ | a64::COND_LS)
                                    if a64::bcond_target(bw, cur + 4) == stream_rel =>
                                {
                                    mid_count += 1;
                                    cur += 8;
                                }
                                Some(a64::COND_NE) if mid_count >= 1 => {
                                    let mut fall = cur + 8;
                                    while fall + 4 <= body.len() && read_u32(body, fall) == a64::NOP {
                                        fall += 4;
                                    }
                                    if fall == stream_rel {
                                        let done_rel = a64::bcond_target(bw, cur + 4);
                                        if let Ok(b_insn) = a64::b(stream_rel + 8, done_rel) {
                                            edits.push(vec![ByteEdit {
                                                offset: start + stream_rel,
                                                payload: words(&[0xaa1f_03e0, 0xaa1f_03e1, b_insn]),
                                            }]);
                                        }
                                    }
                                    break;
                                }
                                _ => break,
                            }
                        }
                    }
                }
            }
            edits
        },
    )
}

fn x86_test_reg8_len(b: &[u8]) -> Option<usize> {
    match b {
        [0x84, m, ..] if (0xc0..=0xff).contains(m) => Some(2),
        [0x40..=0x45, 0x84, m, ..] if (0xc0..=0xff).contains(m) => Some(3),
        _ => None,
    }
}

fn x86_movzbl_rsp_len(b: &[u8]) -> Option<usize> {
    match b {
        [0x0f, 0xb6, m, 0x24, ..] if b.len() >= 5 && m & 0xc7 == 0x44 => Some(5),
        [0x0f, 0xb6, m, 0x24, ..] if b.len() >= 8 && m & 0xc7 == 0x84 => Some(8),
        [0x44, 0x0f, 0xb6, m, 0x24, ..] if b.len() >= 6 && m & 0xc7 == 0x44 => Some(6),
        [0x44, 0x0f, 0xb6, m, 0x24, ..] if b.len() >= 9 && m & 0xc7 == 0x84 => Some(9),
        _ => None,
    }
}

fn x86_mov_imm1_len(b: &[u8]) -> Option<usize> {
    match b {
        [0xb8..=0xbf, 1, 0, 0, 0, ..] => Some(5),
        [0x41, 0xb8..=0xbf, 1, 0, 0, 0, ..] => Some(6),
        _ => None,
    }
}

fn match_cjk_bold_x86(body: &[u8], i: usize) -> Option<(usize, usize)> {
    let t1_len = x86_test_reg8_len(body.get(i..)?)?;
    let br1 = skip_x86_nops(body, i + t1_len);
    let &op1 = body.get(br1)?;
    if op1 != 0x74 && op1 != 0xeb {
        return None;
    }
    let d1 = *body.get(br1 + 1)? as i8;
    if d1 <= 0 {
        return None;
    }
    let else1 = br1 + 2 + d1 as usize;
    if else1 >= body.len() {
        return None;
    }
    // leftFlanking then-블록: 스택 바이트 로드 후 조건/무조건 분기로 after_mov1 합류
    let first_load = skip_x86_nops(body, br1 + 2);
    x86_movzbl_rsp_len(body.get(first_load..)?)?;

    let mut mov1 = skip_x86_nops(body, else1);
    if let Some(n) = x86_movzbl_rsp_len(body.get(mov1..)?) {
        mov1 = skip_x86_nops(body, mov1 + n);
    }
    let m1_len = x86_mov_imm1_len(body.get(mov1..)?)?;
    let after_mov1 = skip_x86_nops(body, mov1 + m1_len);

    // then-블록 끝의 jmp rel8 이 after_mov1 로 합류하는지 확인
    let has_join_jmp = (br1 + 2..else1.saturating_sub(1)).any(|p| {
        body[p] == 0xeb && {
            let d = body[p + 1] as i8;
            d > 0 && {
                let t = p + 2 + d as usize;
                t == mov1 + m1_len || t == after_mov1
            }
        }
    });
    if !has_join_jmp {
        return None;
    }

    let tm_len = x86_test_reg8_len(body.get(after_mov1..)?)?;
    let je2 = skip_x86_nops(body, after_mov1 + tm_len);
    if body.get(je2) != Some(&0x74) {
        return None;
    }
    let d2 = *body.get(je2 + 1)? as i8;
    if d2 <= 0 {
        return None;
    }
    let right_else = je2 + 2 + d2 as usize;
    if right_else >= body.len() {
        return None;
    }
    let mut test2 = skip_x86_nops(body, right_else);
    if let Some(n) = x86_movzbl_rsp_len(body.get(test2..)?) {
        test2 = skip_x86_nops(body, test2 + n);
    }
    let t2_len = x86_test_reg8_len(body.get(test2..)?)?;
    let br2 = skip_x86_nops(body, test2 + t2_len);
    let &op2 = body.get(br2)?;
    if op2 != 0x74 && op2 != 0xeb {
        return None;
    }
    let d3 = *body.get(br2 + 1)? as i8;
    if d3 <= 0 {
        return None;
    }
    let else2 = br2 + 2 + d3 as usize;
    let lim = (else2 + 8).min(body.len());
    let has_mov2 = (else2..lim).any(|p| x86_mov_imm1_len(&body[p..]).is_some());
    has_mov2.then_some((br1, br2))
}

/// ARM64 `tbz wR, #0, +words` 또는 이미 패치된 `b +words`에서 양수 워드 변위 추출
fn a64_tbz_bit0_or_b_words(w: u32) -> Option<u32> {
    if (w & 0xfff8_0000) == 0x3600_0000 {
        let imm14 = (w >> 5) & 0x3fff;
        (3..=10).contains(&imm14).then_some(imm14)
    } else if a64::is_b(w) {
        let imm26 = w & 0x03ff_ffff;
        (3..=10).contains(&imm26).then_some(imm26)
    } else {
        None
    }
}

fn a64_is_mov_imm1(w: u32) -> bool {
    (w & 0xffff_ffe0) == 0xb240_03e0
        || (w & 0xffff_ffe0) == 0x3200_03e0
        || (w & 0xffff_ffe0) == 0x5280_0020
        || (w & 0xffff_ffe0) == 0xd280_0020
}

fn resolve_cjk_bold(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    let label = match ctx.arch {
        Arch::X86_64 => "ScanDelimiter x86_64 플랭킹",
        Arch::Arm64 => "ScanDelimiter ARM64 플랭킹",
    };
    ctx.resolve_in_funcs(
        &["parser.ScanDelimiter"],
        "goldmark/parser/delimiter.go",
        label,
        |start, end| {
            let body = &ctx.data[start..end];
            // `.gopclntab`에서 `unicode.IsSpace` 호출이 보이면 마지막 호출 직후 192바이트 창으로 좁힌다.
            let scan_lo = match ctx.arch {
                Arch::X86_64 => (0..body.len().saturating_sub(5))
                    .rfind(|&p| ctx.call_target_symbol(start + p) == Some("unicode.IsSpace"))
                    .map_or(0, |p| p + 5),
                Arch::Arm64 => (0..body.len().saturating_sub(4))
                    .step_by(4)
                    .rfind(|&p| ctx.call_target_symbol(start + p) == Some("unicode.IsSpace"))
                    .map_or(0, |p| p + 4),
            };
            let scan_hi = if scan_lo > 0 { (scan_lo + 192).min(body.len()) } else { body.len() };

            let mut out = Vec::new();
            match ctx.arch {
                Arch::X86_64 => {
                    for i in scan_lo..scan_hi.saturating_sub(32) {
                        if let Some((br1, br2)) = match_cjk_bold_x86(body, i) {
                            let pair = vec![
                                ByteEdit { offset: start + br1, payload: vec![0xeb] },
                                ByteEdit { offset: start + br2, payload: vec![0xeb] },
                            ];
                            if !out.contains(&pair) {
                                out.push(pair);
                            }
                        }
                    }
                }
                Arch::Arm64 => {
                    for off in (scan_lo..scan_hi.saturating_sub(48)).step_by(4) {
                        let Some(d1) = a64_tbz_bit0_or_b_words(read_u32(body, off)) else {
                            continue;
                        };
                        let else1 = off + (d1 as usize) * 4;
                        if else1 + 24 > body.len() || !a64::is_b(read_u32(body, else1 - 4)) {
                            continue;
                        }
                        let Some(mov1_rel) = (0..=8)
                            .step_by(4)
                            .find(|&k| else1 + k + 4 <= body.len() && a64_is_mov_imm1(read_u32(body, else1 + k)))
                        else {
                            continue;
                        };
                        let after_mov1 = else1 + mov1_rel + 4;
                        for off2 in (after_mov1..(after_mov1 + 40).min(body.len().saturating_sub(16))).step_by(4) {
                            let Some(d2) = a64_tbz_bit0_or_b_words(read_u32(body, off2)) else {
                                continue;
                            };
                            let else2 = off2 + (d2 as usize) * 4;
                            if else2 + 4 <= body.len()
                                && a64::is_b(read_u32(body, else2 - 4))
                                && (0..=8).step_by(4).any(|k| {
                                    else2 + k + 4 <= body.len() && a64_is_mov_imm1(read_u32(body, else2 + k))
                                })
                            {
                                out.push(vec![
                                    ByteEdit {
                                        offset: start + off,
                                        payload: (0x1400_0000u32 | d1).to_le_bytes().to_vec(),
                                    },
                                    ByteEdit {
                                        offset: start + off2,
                                        payload: (0x1400_0000u32 | d2).to_le_bytes().to_vec(),
                                    },
                                ]);
                            }
                        }
                    }
                }
            }
            out
        },
    )
}

fn resolve_tilde_strike(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    let label = match ctx.arch {
        Arch::X86_64 => "strikethroughParser.Parse x86_64",
        Arch::Arm64 => "strikethroughParser.Parse ARM64",
    };
    let require_sym = ctx.pcln.is_some() || ctx.funcs.contains_key("parser.ScanDelimiter");
    ctx.resolve_in_funcs(
        &["extension.(*strikethroughParser).Parse"],
        "goldmark/extension/strikethrough.go",
        label,
        |start, end| {
            let body = &ctx.data[start..end];
            let mut out = Vec::new();
            match ctx.arch {
                Arch::X86_64 => {
                    for call_rel in 5..body.len().saturating_sub(4) {
                        if body[call_rel] != 0xe8 {
                            continue;
                        }
                        if require_sym && ctx.call_target_symbol(start + call_rel) != Some("parser.ScanDelimiter") {
                            continue;
                        }
                        let win_lo = call_rel.saturating_sub(32);
                        if let Some(mov_rel) = (win_lo..call_rel.saturating_sub(4)).rfind(|&p| {
                            body[p] == 0xbe
                                && (body[p + 1] == 0x01 || body[p + 1] == 0x02)
                                && body[p + 2..p + 5] == [0x00, 0x00, 0x00]
                        }) {
                            out.push(vec![ByteEdit {
                                offset: start + mov_rel + 1,
                                payload: vec![0x02],
                            }]);
                        }
                    }
                }
                Arch::Arm64 => {
                    let is_min_arg = |w: u32| {
                        matches!(
                            w,
                            0xb240_03e4
                                | 0x3200_03e4
                                | 0xd280_0024
                                | 0x5280_0024
                                | 0xb27f_03e4
                                | 0x321f_03e4
                                | 0xd280_0044
                                | 0x5280_0044
                        )
                    };
                    for call_rel in (4..body.len().saturating_sub(3)).step_by(4) {
                        if !a64::is_bl(read_u32(body, call_rel)) {
                            continue;
                        }
                        if require_sym && ctx.call_target_symbol(start + call_rel) != Some("parser.ScanDelimiter") {
                            continue;
                        }
                        let win_lo = call_rel.saturating_sub(32);
                        if let Some(mov_rel) = (win_lo..call_rel)
                            .step_by(4)
                            .rfind(|&p| is_min_arg(read_u32(body, p)))
                        {
                            out.push(vec![ByteEdit {
                                offset: start + mov_rel,
                                payload: 0xb27f_03e4u32.to_le_bytes().to_vec(), // orr x4, xzr, #2
                            }]);
                        }
                    }
                }
            }
            out
        },
    )
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

/// 문자열 VA 역추적 결과: 원본 `"native"` 이거나 이미 패치되어 `<style name="..."` 안을 가리키는 경우만 참
fn is_code_theme_target(data: &[u8], str_off: usize, str_len: usize) -> bool {
    if !(1..=64).contains(&str_len) {
        return false;
    }
    let Some(bytes) = data.get(str_off..str_off + str_len) else {
        return false;
    };
    if bytes == b"native" {
        return true;
    }
    const PREFIX: &[u8] = b"<style name=\"";
    str_off >= PREFIX.len()
        && &data[str_off - PREFIX.len()..str_off] == PREFIX
        && data.get(str_off + str_len) == Some(&b'"')
        && std::str::from_utf8(bytes).is_ok()
}

struct CodeThemeSite {
    lea_disp_off: usize,
    lea_next_off: usize,
    len_imm_off: usize,
}

struct A64CodeThemeSite {
    adrp_off: usize,
    ptr_reg: u32,
    len_off: usize,
    len_reg: u32,
}

const A64_ORR_IMM6: u32 = 0xb27f_07e0; // orr xL, xzr, #0x6 (원본 "native" 길이)

fn find_code_theme_site_a64(ctx: &BinaryContext) -> Result<A64CodeThemeSite, String> {
    let d = ctx.data;
    ctx.resolve_in_funcs(
        &["render.glamourStyleForScheme", "render.glamourStyle"],
        "cli/render/markdown.go",
        "glamourStyleForScheme ARM64 terminal 테마",
        |start, end| {
            let mut matches = Vec::new();
            let mut off = start;
            while off + 16 <= end {
                let Some((p, str_off)) = ctx.a64_adrp_add_target_off(off) else {
                    off += 4;
                    continue;
                };
                let scan_end = (off + 28).min(end);
                let mut len_hit = None;
                let mut k = off + 8;
                while k + 4 <= scan_end {
                    let lw = word(d, k);
                    let l = a64::rd(lw);
                    if l != p && a64::is_movz(lw) {
                        len_hit = Some((k, l, a64::imm16(lw) as usize));
                        break;
                    } else if l != p && (lw & !31) == A64_ORR_IMM6 {
                        len_hit = Some((k, l, 6usize));
                        break;
                    }
                    k += 4;
                }
                if let Some((len_off, l, cur_len)) = len_hit {
                    let stp_ok = ((off + 8)..scan_end).step_by(4).any(|pos| {
                        let s = word(d, pos);
                        s & 0xffc0_0000 == 0xa900_0000 && (s & 31) == p && ((s >> 10) & 31) == l
                    });
                    if stp_ok && is_code_theme_target(d, str_off, cur_len) {
                        matches.push(A64CodeThemeSite {
                            adrp_off: off,
                            ptr_reg: p,
                            len_off,
                            len_reg: l,
                        });
                    }
                }
                off += 4;
            }
            matches
        },
    )
}

fn detect_patched_code_theme_a64(ctx: &BinaryContext) -> Option<String> {
    let site = find_code_theme_site_a64(ctx).ok()?;
    let d = ctx.data;
    let (_, str_off) = ctx.a64_adrp_add_target_off(site.adrp_off)?;
    let len_w = word(d, site.len_off);
    let len = if a64::is_movz(len_w) { a64::imm16(len_w) as usize } else { 6 };
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
    ctx.resolve_in_funcs(
        &["render.glamourStyleForScheme", "render.glamourStyle"],
        "cli/render/markdown.go",
        "glamourStyleForScheme terminal 테마",
        |start, end| {
            let body = &ctx.data[start..end];
            let mut matches = Vec::new();
            for lea_rel in 0..body.len().saturating_sub(20) {
                let Some((ptr_reg, str_off)) = ctx.x86_lea_target_off(start + lea_rel) else {
                    continue;
                };
                let s1 = skip_x86_nops(body, lea_rel + 7);
                // (ptr 저장 -> len 저장) 또는 (len 저장 -> ptr 저장) 모두 허용
                let hit = if let Some((n1, reg, sp_ptr)) = x86_rsp_store_info(&body[s1..]) {
                    let s2 = skip_x86_nops(body, s1 + n1);
                    x86_rsp_imm_store_info(&body[s2..])
                        .filter(|&(_, sp_len, _, _)| reg == ptr_reg && sp_ptr.saturating_add(8) == sp_len)
                        .map(|(_, _, imm_rel, cur_len)| (s2 + imm_rel, cur_len as usize))
                } else if let Some((n1, sp_len, imm_rel, cur_len)) = x86_rsp_imm_store_info(&body[s1..]) {
                    let s2 = skip_x86_nops(body, s1 + n1);
                    x86_rsp_store_info(&body[s2..])
                        .filter(|&(_, reg, sp_ptr)| reg == ptr_reg && sp_ptr.saturating_add(8) == sp_len)
                        .map(|_| (s1 + imm_rel, cur_len as usize))
                } else {
                    None
                };
                if let Some((len_imm_rel, cur_len)) = hit {
                    if is_code_theme_target(ctx.data, str_off, cur_len) {
                        matches.push(CodeThemeSite {
                            lea_disp_off: start + lea_rel + 3,
                            lea_next_off: start + lea_rel + 7,
                            len_imm_off: start + len_imm_rel,
                        });
                    }
                }
            }
            matches
        },
    )
}

fn detect_patched_code_theme(ctx: &BinaryContext) -> Option<String> {
    if ctx.arch == Arch::Arm64 {
        return detect_patched_code_theme_a64(ctx);
    }
    let site = find_code_theme_site(ctx).ok()?;
    let (_, str_off) = ctx.x86_lea_target_off(site.lea_disp_off - 3)?;
    let len = read_u32(ctx.data, site.len_imm_off) as usize;
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

fn x86_indirect_call_len(b: &[u8]) -> Option<usize> {
    match b {
        [0xff, m, ..] if (0xd0..=0xd7).contains(m) => Some(2),
        [0x41, 0xff, m, ..] if (0xd0..=0xd7).contains(m) => Some(3),
        _ => None,
    }
}

/// `cmp $imm32, r32` -> `(명령 길이, imm32 상대 오프셋, imm32 값)`
fn x86_cmp_imm32(b: &[u8]) -> Option<(usize, usize, u32)> {
    match b {
        [0x3d, ..] if b.len() >= 5 => Some((5, 1, read_u32(b, 1))),
        [0x81, m, ..] if b.len() >= 6 && (0xf8..=0xff).contains(m) => Some((6, 2, read_u32(b, 2))),
        [0x41, 0x81, m, ..] if b.len() >= 7 && (0xf8..=0xff).contains(m) => Some((7, 3, read_u32(b, 3))),
        _ => None,
    }
}

/// `mov $imm32, r32` -> `(명령 길이, imm32 상대 오프셋, imm32 값)`
fn x86_mov_imm32(b: &[u8]) -> Option<(usize, usize, u32)> {
    match b {
        [0xb8..=0xbf, ..] if b.len() >= 5 => Some((5, 1, read_u32(b, 1))),
        [0x41, 0xb8..=0xbf, ..] if b.len() >= 6 => Some((6, 2, read_u32(b, 2))),
        _ => None,
    }
}

fn x86_is_cmov_limit(b: &[u8]) -> bool {
    match b {
        [0x0f, op @ (0x42 | 0x46 | 0x4c | 0x4e), m, ..] => (0xc0..=0xff).contains(m) && {
            let _ = op;
            true
        },
        [0x41 | 0x44 | 0x45, 0x0f, 0x42 | 0x46 | 0x4c | 0x4e, m, ..] => (0xc0..=0xff).contains(m),
        _ => false,
    }
}

/// `cmpl $0, disp(rPtr)` -> 명령 길이
fn x86_cmp_mem_zero_len(b: &[u8]) -> Option<usize> {
    let (p, rest) = if matches!(b.first(), Some(0x41)) { (1usize, &b[1..]) } else { (0usize, b) };
    if rest.first() != Some(&0x83) || rest.len() < 4 {
        return None;
    }
    let m = rest[1];
    if ((m >> 3) & 7) != 7 {
        return None;
    }
    let sib = usize::from((m & 7) == 4);
    let len = match m & 0xc0 {
        0x40 => 3 + sib + 1,
        0x80 => 2 + sib + 4 + 1,
        _ => return None,
    };
    (rest.get(len - 1) == Some(&0x00)).then_some(p + len)
}

/// `movl $imm32, 0xc(rCfg)` -> `(명령 길이, imm32 상대 오프셋, imm32 값)`
fn x86_mov_mem_0c_imm32(b: &[u8]) -> Option<(usize, usize, u32)> {
    let (p, rest) = if matches!(b.first(), Some(0x41)) { (1usize, &b[1..]) } else { (0usize, b) };
    if rest.len() < 7 || rest[0] != 0xc7 || (rest[1] & 0xf8) != 0x40 || (rest[1] & 7) == 4 || rest[2] != 0x0c {
        return None;
    }
    Some((p + 7, p + 3, read_u32(rest, 3)))
}

fn find_compact_sites(ctx: &BinaryContext) -> Result<CompactSites, String> {
    if ctx.arch == Arch::Arm64 {
        return find_compact_sites_a64(ctx);
    }

    let need_checkpoint_callee =
        !ctx.funcs.contains_key("config.applyFeatureProviderCheckpointOverrideConfig") && ctx.pcln.is_some();
    let (override_branch_off, is_override_patched, override_patch) = ctx.resolve_in_funcs(
        &["config.applyFeatureProviderCheckpointOverrideConfig"],
        "cortex/config/experiments.go",
        "applyFeatureProviderCheckpointOverrideConfig 분기",
        |ov_start, ov_end| {
            let ov_body = &ctx.data[ov_start..ov_end];
            if need_checkpoint_callee
                && !(0..ov_body.len().saturating_sub(5)).any(|p| {
                    ctx.call_target_symbol(ov_start + p)
                        .is_some_and(|sym| sym.contains("Checkpoint"))
                })
            {
                return Vec::new();
            }
            let mut ov_matches = Vec::new();
            for i in 0..ov_body.len().saturating_sub(8) {
                let Some(call_len) = x86_indirect_call_len(&ov_body[i..]) else {
                    continue;
                };
                let test_pos = skip_x86_nops(ov_body, i + call_len);
                if ov_body.get(test_pos..test_pos + 2) != Some(&[0x84, 0xc0]) {
                    continue;
                }
                let test_end = test_pos + 2;
                let jcc = skip_x86_nops(ov_body, test_end);
                if let Some(&0x75) = ov_body.get(jcc) {
                    let d = ov_body.get(jcc + 1).copied().unwrap_or(0) as usize;
                    let after = jcc + 2;
                    let target = (after + d).min(ov_body.len());
                    let false_blk = ov_body.get(after..target).unwrap_or(&[]);
                    let valid = (2..=32).contains(&d)
                        && (x86_rsp_load_len(false_blk).is_some()
                            || false_blk.contains(&0xeb)
                            || false_blk.contains(&0xe9));
                    if valid {
                        ov_matches.push((ov_start + jcc, false, vec![0x90, 0x90]));
                    }
                } else if jcc >= test_end + 2
                    && ov_body.get(jcc - 2..jcc) == Some(&[0x90, 0x90])
                    && ov_body.get(jcc..).is_some_and(|r| {
                        x86_rsp_load_len(r).is_some() || matches!(r.first(), Some(0xeb | 0xe9))
                    })
                {
                    ov_matches.push((ov_start + jcc - 2, true, vec![0x90, 0x90]));
                }
            }
            ov_matches.dedup();
            ov_matches
        },
    )?;

    let (slot1_off, slot2_off, slot3_off, current_tokens) = ctx.resolve_in_funcs(
        &["utils.GetCheckpointConfig"],
        "cortex/utils/checkpoint_utils.go",
        "GetCheckpointConfig 상한/폴백",
        |gc_start, gc_end| {
            let gc_body = &ctx.data[gc_start..gc_end];
            let mut limit_matches = Vec::new();
            for i in 0..gc_body.len().saturating_sub(13) {
                let Some((c_len, c_imm_rel, v1)) = x86_cmp_imm32(&gc_body[i..]) else {
                    continue;
                };
                if !(MIN_COMPACT_TOKENS..=MAX_COMPACT_TOKENS).contains(&v1) {
                    continue;
                }
                let mov_pos = skip_x86_nops(gc_body, i + c_len);
                let Some((m_len, m_imm_rel, v2)) = x86_mov_imm32(gc_body.get(mov_pos..).unwrap_or(&[])) else {
                    continue;
                };
                let cmov_pos = skip_x86_nops(gc_body, mov_pos + m_len);
                if v1 == v2 && x86_is_cmov_limit(gc_body.get(cmov_pos..).unwrap_or(&[])) {
                    limit_matches.push((gc_start + i + c_imm_rel, gc_start + mov_pos + m_imm_rel, v1));
                }
            }
            limit_matches.dedup();
            if limit_matches.len() != 1 {
                return Vec::new();
            }
            let (s1, s2, cur_tok) = limit_matches[0];

            let mut fb_matches = Vec::new();
            for i in 0..gc_body.len().saturating_sub(12) {
                let Some(cmp_len) = x86_cmp_mem_zero_len(&gc_body[i..]) else {
                    continue;
                };
                let jg_pos = skip_x86_nops(gc_body, i + cmp_len);
                let Some(&jg_op) = gc_body.get(jg_pos) else {
                    continue;
                };
                if jg_op != 0x7f && jg_op != 0x7d {
                    continue;
                }
                let skip = gc_body.get(jg_pos + 1).copied().unwrap_or(0) as usize;
                let jg_target = jg_pos + 2 + skip;
                let mov_pos = skip_x86_nops(gc_body, jg_pos + 2);
                if let Some((mov_len, imm_rel, v3)) = x86_mov_mem_0c_imm32(gc_body.get(mov_pos..).unwrap_or(&[])) {
                    let mov_end = mov_pos + mov_len;
                    if v3 == cur_tok && (jg_target == mov_end || jg_target == skip_x86_nops(gc_body, mov_end)) {
                        fb_matches.push((s1, s2, gc_start + mov_pos + imm_rel, cur_tok));
                    }
                }
            }
            fb_matches.dedup();
            fb_matches
        },
    )?;

    Ok(CompactSites {
        override_branch_off,
        override_patch,
        is_override_patched,
        slots: [
            CompactSlot::Imm32(slot1_off),
            CompactSlot::Imm32(slot2_off),
            CompactSlot::Imm32(slot3_off),
        ],
        current_tokens,
    })
}

fn a64_is_ov_branch(w: u32) -> bool {
    // tbnz w0, #0, +2..8워드 또는 cbnz w0, +2..8워드
    ((w & 0xfff8_001f) == 0x3700_0000 && (2..=8).contains(&((w >> 5) & 0x3fff)))
        || ((w & 0xff00_001f) == 0x3500_0000 && (2..=8).contains(&((w >> 5) & 0x7ffff)))
}

fn find_compact_sites_a64(ctx: &BinaryContext) -> Result<CompactSites, String> {
    let d = ctx.data;

    let need_checkpoint_callee =
        !ctx.funcs.contains_key("config.applyFeatureProviderCheckpointOverrideConfig") && ctx.pcln.is_some();
    let (override_branch_off, is_override_patched) = ctx.resolve_in_funcs(
        &["config.applyFeatureProviderCheckpointOverrideConfig"],
        "cortex/config/experiments.go",
        "applyFeatureProviderCheckpointOverrideConfig ARM64 분기",
        |ov_start, ov_end| {
            if need_checkpoint_callee
                && !(ov_start..ov_end.saturating_sub(4)).step_by(4).any(|p| {
                    ctx.call_target_symbol(p)
                        .is_some_and(|sym| sym.contains("Checkpoint"))
                })
            {
                return Vec::new();
            }
            let mut ov_matches = Vec::new();
            let mut off = ov_start;
            while off + 16 <= ov_end {
                let (w0, w1) = (word(d, off), word(d, off + 4));
                if w0 & 0xffff_fc1f == 0xd63f_0000 && (a64_is_ov_branch(w1) || w1 == a64::NOP) {
                    let scan_end = (off + 28).min(ov_end);
                    let has_b = ((off + 8)..scan_end).step_by(4).any(|p| a64::is_b(word(d, p)));
                    if has_b {
                        ov_matches.push((off + 4, w1 == a64::NOP));
                    }
                }
                off += 4;
            }
            ov_matches
        },
    )?;

    let (slot1_off, slot2_off, limit_reg, slot3_off, fallback_reg, current_tokens) = ctx.resolve_in_funcs(
        &["utils.GetCheckpointConfig"],
        "cortex/utils/checkpoint_utils.go",
        "GetCheckpointConfig ARM64 상한/폴백",
        |gc_start, gc_end| {
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
                return Vec::new();
            }
            let (s1, s2, lreg, cur_tok) = limit_matches[0];

            let mut fb_matches = Vec::new();
            let mut off = gc_start + 4;
            while off + 12 <= gc_end {
                let prev = word(d, off - 4);
                let skip_ok = a64::bcond(prev) == Some(a64::COND_GT) && a64::bcond_target(prev, off - 4) == off + 12;
                if let Some((r, v)) = a64_mov32_pair(d, off) {
                    let st = word(d, off + 8);
                    if skip_ok && v == cur_tok && st & 0xffff_fc00 == 0xb900_0c00 && st & 31 == r {
                        fb_matches.push((s1, s2, lreg, off, r, cur_tok));
                    }
                }
                off += 4;
            }
            fb_matches
        },
    )?;

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

// --- pro-tier / flash-tier / flash-lite-tier: 서브에이전트 모델 티어 고정 ---
//
// invoke_subagent·사용자 정의 에이전트(model: pro)·훅 등은 모델을 티어(inherit/flash_lite/flash/pro)로만 받고,
// modelutils.modelIDForTier 가 서버가 계정별로 내려주는 TieredModelConfig 의 티어별 모델 목록 첫 항목을 고른다.
// 로컬에서 이 목록을 덮는 설정(admin_settings.json models.tiers, AGY_LLM_GATEWAY_TIER_*)은 LLM 게이트웨이
// 모드에서만 읽히므로(gateway.applyConfiguredModelTiers 가 유일한 사용처, 정적 분석 기준), 티어 분기가 지정한
// 모델 ID 를 바로 돌려주게 바꾼다. agy 유틸리티 모델은 flash_lite, 없으면 flash 티어를 쓰므로 그 두 티어를
// 고정하면 유틸리티 작업도 같은 모델을 쓴다.

/// 고정할 수 있는 티어. `tier` 는 exa.cortex_pb.ModelTier 값.
struct TierSpec {
    id: &'static str,
    flag: &'static str,
    /// `--tiers` 출력과 decision 훅 AGY_TIER_MODELS 의 키
    key: &'static str,
    /// 대화형 화면 알림 문구 ("pro 티어 모델: …", "pro 티어 모델이 '…'(으)로 …")
    label: &'static str,
    subject: &'static str,
    tier: u8,
    default_model: &'static str,
}

/// BinaryContext::tier_models·PatchArgs::tiers 와 같은 순서
const TIERS: [TierSpec; 3] = [
    TierSpec {
        id: "pro-tier",
        flag: "--pro-tier",
        key: "pro",
        label: "pro 티어 모델",
        subject: "pro 티어 모델이",
        tier: 4,
        default_model: "gemini-4-carbon-high",
    },
    TierSpec {
        id: "flash-tier",
        flag: "--flash-tier",
        key: "flash",
        label: "flash 티어 모델",
        subject: "flash 티어 모델이",
        tier: 3,
        default_model: "gemini-4-neon-medium",
    },
    TierSpec {
        id: "flash-lite-tier",
        flag: "--flash-lite-tier",
        key: "flash_lite",
        label: "flash_lite 티어 모델",
        subject: "flash_lite 티어 모델이",
        tier: 2,
        default_model: "gemini-4-hydrogen-low",
    },
];

fn tier_index(id: &str) -> Option<usize> {
    TIERS.iter().position(|t| t.id == id)
}

fn default_tier_models() -> [String; 3] {
    TIERS.map(|t| t.default_model.to_string())
}
/// 대화형 화면에서 -/+ 로 고르는 후보 (`agy models` 기준, 오케스트레이터 전용 모델 제외).
/// invoke_subagent 에는 effort 인자가 없어 사고 수준은 ID 끝(-low/-medium/-high/-xhigh)으로 정해진다.
/// 시작할 때 이 바이너리에 문자열로 들어 있는 것만 남긴다. 여기 없는 새 모델은 e 로 직접 입력한다.
const KNOWN_MODEL_IDS: &[&str] = &[
    "gemini-4-carbon-high",
    "gemini-4-carbon-medium",
    "gemini-4-carbon-low",
    "gemini-4-hydrogen-xhigh",
    "gemini-4-hydrogen-high",
    "gemini-4-hydrogen-medium",
    "gemini-4-hydrogen-low",
    "gemini-4-neon-xhigh",
    "gemini-4-neon-high",
    "gemini-4-neon-medium",
    "gemini-4-neon-low",
    "gemini-4-argon-high",
    "gemini-4-argon-medium",
    "gemini-4-argon-low",
    "claude-opus-5-5-high",
    "claude-opus-5-5-medium",
    "claude-opus-5-5-low",
    "claude-sonnet-5-5-high",
    "claude-sonnet-5-5-medium",
    "claude-sonnet-5-5-low",
    "gemini-3.8-flash-high",
    "gemini-3.8-flash-medium",
    "gemini-3.8-flash-low",
];
const MODEL_ID_EXAMPLES: &str = "gemini-4-carbon-high, gemini-4-neon-medium, gemini-4-hydrogen-low";

fn parse_model_id(raw: &str) -> Result<String, String> {
    let id = raw.trim().to_ascii_lowercase();
    let valid = !id.is_empty()
        && id.len() <= 64
        && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.' | '_'));
    if !valid {
        return Err(format!(
            "유효하지 않은 모델 ID 입니다: '{raw}' (영문 소문자·숫자·'-'·'.'·'_', 예: {MODEL_ID_EXAMPLES})"
        ));
    }
    Ok(id)
}

/// 모델 ID 를 찾을 범위. 패치한 코드가 가리킬 것이므로 modelIDForTier 와 같은 (실행) 세그먼트로 한정한다.
fn model_id_search_range(ctx: &BinaryContext) -> Result<(usize, usize), String> {
    let func = ctx
        .get_func("modelutils.modelIDForTier")
        .map(|(s, _)| s)
        .or_else(|e| {
            ctx.pcln
                .and_then(|p| p.funcs_in_file(ctx.data, "cortex/modelutils/model_tier.go").first().map(|&(s, _)| s))
                .ok_or(e)
        })?;
    Ok(ctx
        .segments
        .iter()
        .find(|&&(off, _, size)| func >= off && func - off < size)
        .map_or((0, ctx.data.len()), |&(off, _, size)| (off, off + size)))
}

/// `needle` 이 나오는 모든 위치. 첫 바이트로 건너뛰므로 수백 MB 에서도 windows() 비교보다 훨씬 빠르다.
fn find_all<'a>(haystack: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    let first = needle.first().copied();
    let mut i = 0;
    std::iter::from_fn(move || {
        let first = first?;
        while i + needle.len() <= haystack.len() {
            let at = i + haystack[i..].iter().position(|&b| b == first)?;
            i = at + 1;
            if haystack[at..].starts_with(needle) {
                return Some(at);
            }
        }
        None
    })
}

/// 모델 ID 문자열이 들어 있는 위치.
/// Go 문자열은 길이를 따로 들고 다니므로 다른 문자열 사이에 붙어 있어도 된다.
fn find_model_id_offset(ctx: &BinaryContext, model: &str) -> Result<usize, String> {
    let (lo, hi) = model_id_search_range(ctx)?;
    find_all(&ctx.data[lo..hi], model.as_bytes())
        .next()
        .map(|p| lo + p)
        .ok_or_else(|| format!("바이너리에 '{model}' 모델 ID 문자열이 없어 쓸 수 없습니다 (예: {MODEL_ID_EXAMPLES})"))
}

/// KNOWN_MODEL_IDS 중 이 바이너리에 들어 있는 것 (순서 유지). 접두어마다 한 번만 훑는다.
fn available_model_ids(ctx: &BinaryContext) -> Vec<&'static str> {
    let Ok((lo, hi)) = model_id_search_range(ctx) else {
        return Vec::new();
    };
    let hay = &ctx.data[lo..hi];
    let mut found = vec![false; KNOWN_MODEL_IDS.len()];
    for prefix in ["gemini-", "claude-"] {
        for at in find_all(hay, prefix.as_bytes()) {
            for (k, id) in KNOWN_MODEL_IDS.iter().enumerate() {
                if !found[k] && id.starts_with(prefix) && hay[at..].starts_with(id.as_bytes()) {
                    found[k] = true;
                }
            }
        }
    }
    KNOWN_MODEL_IDS.iter().zip(found).filter_map(|(id, ok)| ok.then_some(*id)).collect()
}

/// modelIDForTier 의 티어 분기 본문 (`cmp $tier, r32; jne ..` 바로 뒤).
/// 반환값: (본문 시작, 본문 길이, 이미 패치됐는지)
fn find_tier_site_x86(ctx: &BinaryContext, tier: u8) -> Result<(usize, usize, bool), String> {
    const NIL_BLOCK: [u8; 7] = [0x31, 0xf6, 0x31, 0xd2, 0x48, 0x85, 0xf6]; // xor %esi,%esi; xor %edx,%edx; test %rsi,%rsi
    const LOAD: [u8; 7] = [0x48, 0x8b, 0x02, 0x48, 0x8b, 0x5a, 0x08]; // mov (%rdx),%rax; mov 8(%rdx),%rbx
    const RET: [u8; 6] = [0x31, 0xc9, 0x31, 0xff, 0xc9, 0xc3]; // error = nil; leave; ret
    let label = format!("modelIDForTier 티어 {tier} 분기");
    ctx.resolve_in_funcs(
        &["modelutils.modelIDForTier"],
        "cortex/modelutils/model_tier.go",
        &label,
        |start, end| {
            let body = &ctx.data[start..end];
            let mut matches = Vec::new();
            for i in 0..body.len().saturating_sub(24) {
                let Some((cmp_len, imm)) = x86_cmp_imm8(&body[i..]) else {
                    continue;
                };
                if imm != tier {
                    continue;
                }
                let jne_pos = skip_x86_nops(body, i + cmp_len);
                let Some((5, jne_next, _)) = x86_jcc_target(body, jne_pos) else {
                    continue;
                };
                let b = skip_x86_nops(body, jne_next);
                if b + 18 > body.len() {
                    continue;
                }
                let w = &body[b..];
                let unpatched_nil = if w.starts_with(&[0x48, 0x85, 0xc0, 0x74]) {
                    let nil_off = 5 + w[4] as usize;
                    let fields_ok = if nil_off == 15 {
                        w.get(5..8) == Some(&[0x48, 0x8b, 0x50])
                            && w.get(9..12) == Some(&[0x48, 0x8b, 0x70])
                            && w[8].wrapping_add(8) == w[12]
                    } else if nil_off == 21 && w.len() >= 21 {
                        w[5..8] == [0x48, 0x8b, 0x90]
                            && w[12..15] == [0x48, 0x8b, 0xb0]
                            && read_i32(w, 8).wrapping_add(8) == read_i32(w, 15)
                    } else {
                        false
                    };
                    (fields_ok
                        && nil_off >= 7
                        && w.get(nil_off - 2..nil_off) == Some(&[0xeb, 0x04])
                        && w.get(nil_off..nil_off + 7) == Some(&NIL_BLOCK))
                    .then_some(nil_off + 7)
                } else {
                    None
                };
                let found = if let Some(chk) = unpatched_nil.map(|p| skip_x86_nops(w, p)) {
                    if let Some((5, after_jne, ok)) = x86_jcc_target(w, chk) {
                        (w.get(ok..ok + 7) == Some(&LOAD[..])).then_some((after_jne, false))
                    } else if let Some((4, after_je, _)) = x86_jcc_target(w, chk) {
                        let ld = skip_x86_nops(w, after_je);
                        (w.get(ld..ld + 7) == Some(&LOAD[..]) && w.get(ld + 7..ld + 13) == Some(&RET[..]))
                            .then_some((ld + 13, false))
                    } else {
                        None
                    }
                } else if w[0..3] == [0x48, 0x8d, 0x05] && w[7] == 0xbb && w[12..18] == RET {
                    // 이미 패치됨: 원래 본문 길이는 뒤따르는 int3 개수로 되찾는다
                    let n = 18 + w[18..].iter().take_while(|&&c| c == 0xcc).count();
                    (18..=64).contains(&n).then_some((n, true))
                } else {
                    None
                };
                if let Some((n, patched)) = found {
                    matches.push((start + b, n, patched));
                }
            }
            matches
        },
    )
}

/// ARM64 modelIDForTier 의 티어 분기 (`cmp wR, #tier; b.ne ..` 바로 뒤).
/// 반환값: (본문 시작, 반환 꼬리 위치, 이미 패치됐는지)
fn find_tier_site_a64(ctx: &BinaryContext, tier: u8) -> Result<(usize, usize, bool), String> {
    const LDP_X0_X1_X4: u32 = 0xa940_0480;
    let d = ctx.data;
    let is_ret_tail = |t: usize| {
        t + 20 <= d.len()
            && word(d, t) == 0xaa1f_03e2
            && word(d, t + 4) == 0xaa1f_03e3
            && word(d, t + 8) == 0xf85f_83fd
            && word(d, t + 12) & 0xffe0_0fff == 0xf840_07fe
            && word(d, t + 16) == 0xd65f_03c0
    };
    let cmp_mask = 0x7100_001f | (u32::from(tier) << 10);
    let label = format!("modelIDForTier ARM64 티어 {tier} 분기");
    ctx.resolve_in_funcs(
        &["modelutils.modelIDForTier"],
        "cortex/modelutils/model_tier.go",
        &label,
        |start, end| {
            let mut matches = Vec::new();
            let mut off = start;
            while off + 8 + 24 <= end {
                if (word(d, off) & 0xffff_fc1f) != cmp_mask || a64::bcond(word(d, off + 4)) != Some(a64::COND_NE) {
                    off += 4;
                    continue;
                }
                let body = off + 8;
                let w = |k: usize| word(d, body + k * 4);
                let head = w(0) == 0xb400_0060
                    && w(1) & 0xffc0_7fff == 0xa940_1404
                    && w(2) == 0x1400_0003
                    && w(3) == 0xaa1f_03e5
                    && w(4) == 0xaa1f_03e4;
                let found =
                    if head && w(5) & 0xff00_001f == 0xb400_0005 && w(6) == LDP_X0_X1_X4 && is_ret_tail(body + 28) {
                        Some((body + 28, false))
                    } else if head && w(5) & 0xff00_001f == 0xb500_0005 {
                        let ok = a64::bcond_target(w(5), body + 20); // cbnz 도 imm19 위치가 b.cond 와 같다
                        (ok + 4 <= d.len() && word(d, ok) == LDP_X0_X1_X4 && is_ret_tail(ok + 4))
                            .then_some((ok + 4, false))
                    } else if a64::is_adrp(w(0))
                        && a64::rd(w(0)) == 0
                        && a64::is_add_imm(w(1))
                        && a64::rd(w(1)) == 0
                        && a64::add_rn(w(1)) == 0
                        && a64::is_movz(w(2))
                        && a64::rd(w(2)) == 1
                        && a64::is_b(w(3))
                    {
                        // 이미 패치됨: b 의 목적지가 반환 꼬리
                        ctx.off_to_va(body + 12)
                            .map(|pc| a64::branch26_target(w(3), pc))
                            .and_then(|t| ctx.va_to_off(t))
                            .filter(|&t| is_ret_tail(t))
                            .map(|t| (t, true))
                    } else {
                        None
                    };
                if let Some((tail, patched)) = found {
                    matches.push((body, tail, patched));
                }
                off += 4;
            }
            matches
        },
    )
}

/// 이 바이너리에서 티어 분기를 찾을 수 있는지 (아키텍처별)
fn tier_site_found(ctx: &BinaryContext, tier: u8) -> bool {
    match ctx.arch {
        Arch::X86_64 => find_tier_site_x86(ctx, tier).is_ok(),
        Arch::Arm64 => find_tier_site_a64(ctx, tier).is_ok(),
    }
}

/// 이미 티어 고정 패치가 돼 있으면 고정된 모델 ID
fn detect_patched_tier(ctx: &BinaryContext, ti: usize) -> Option<String> {
    let tier = TIERS[ti].tier;
    let (str_va, len) = match ctx.arch {
        Arch::X86_64 => {
            let (site, _, true) = find_tier_site_x86(ctx, tier).ok()? else {
                return None;
            };
            let pc = ctx.off_to_va(site + 7)? as i64;
            (usize::try_from(pc + read_i32(ctx.data, site + 3) as i64).ok()?, read_u32(ctx.data, site + 8) as usize)
        }
        Arch::Arm64 => {
            let (body, _, true) = find_tier_site_a64(ctx, tier).ok()? else {
                return None;
            };
            let page = a64::adrp_target(word(ctx.data, body), ctx.off_to_va(body)?);
            (page + a64::add_imm12(word(ctx.data, body + 4)), a64::imm16(word(ctx.data, body + 8)) as usize)
        }
    };
    let str_off = ctx.va_to_off(str_va)?;
    std::str::from_utf8(ctx.data.get(str_off..str_off + len)?).ok().map(str::to_string)
}

fn resolve_tier(ctx: &BinaryContext, ti: usize) -> Result<Vec<ByteEdit>, String> {
    let spec = &TIERS[ti];
    let model = &ctx.tier_models[ti];
    let model_off = find_model_id_offset(ctx, model)?;
    let model_va = ctx.off_to_va(model_off).ok_or("모델 ID 문자열 가상주소 변환 실패")?;
    match ctx.arch {
        Arch::X86_64 => {
            let (site, len, _) = find_tier_site_x86(ctx, spec.tier)?;
            let pc = ctx.off_to_va(site + 7).ok_or("LEA 명령어 가상주소 변환 실패")?;
            let disp = i32::try_from(model_va as i64 - pc as i64).map_err(|_| "RIP 상대 변위 범위 초과".to_string())?;
            let mut code = vec![0x48, 0x8d, 0x05]; // lea model(%rip),%rax
            code.extend_from_slice(&disp.to_le_bytes());
            code.push(0xbb); // mov $len,%ebx
            code.extend_from_slice(&(model.len() as u32).to_le_bytes());
            code.extend_from_slice(&[0x31, 0xc9, 0x31, 0xff, 0xc9, 0xc3]); // error = nil; leave; ret
            code.resize(len, 0xcc);
            Ok(vec![ByteEdit { offset: site, payload: code }])
        }
        Arch::Arm64 => {
            let (body, tail, _) = find_tier_site_a64(ctx, spec.tier)?;
            let pc = ctx.off_to_va(body).ok_or("ADRP 명령어 가상주소 변환 실패")?;
            let tail_va = ctx.off_to_va(tail).ok_or("반환 꼬리 가상주소 변환 실패")?;
            Ok(vec![ByteEdit {
                offset: body,
                payload: words(&[
                    a64::adrp(0, pc, model_va)?,
                    a64::add_imm(0, 0, model_va & 0xfff),
                    a64::movz(1, model.len() as u32),
                    a64::b(pc + 12, tail_va)?,
                ]),
            }])
        }
    }
}

/// `--tiers` 출력: 이 바이너리에 고정된 티어만 `pro=…,flash=…,flash_lite=…` 로 (없으면 빈 문자열).
/// decision 훅이 AGY_TIER_MODELS 와 같은 문법으로 읽고, 빠진 티어는 서버 기본값으로 둔다.
fn tier_query_line(ctx: &BinaryContext) -> String {
    TIERS
        .iter()
        .enumerate()
        .filter_map(|(ti, t)| detect_patched_tier(ctx, ti).map(|m| format!("{}={m}", t.key)))
        .collect::<Vec<_>>()
        .join(",")
}

fn resolve_pro_tier(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    resolve_tier(ctx, 0)
}

fn resolve_flash_tier(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    resolve_tier(ctx, 1)
}

fn resolve_flash_lite_tier(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    resolve_tier(ctx, 2)
}

// banner / patch-info 패치가 공유하는 0xcc 패딩 공간(cave) 배치.
// 두 패치를 따로 적용해도 겹치지 않도록 고정 오프셋을 쓴다.
const CAVE_MIN: usize = 1024;
const CAVE_CHAN_OFF: usize = 0; // "patch v{ver}" (≤ 32바이트)
const CAVE_INFO_OFF: usize = 64; // 적용 패치 정보 문자열 + 트램펄린

fn find_cave(ctx: &BinaryContext) -> Result<usize, String> {
    let needle = [0xccu8; CAVE_MIN];
    ctx.data
        .windows(needle.len())
        .position(|w| w == needle)
        .ok_or_else(|| format!("실행 파일 내 0xcc 여유 공간({CAVE_MIN}바이트)을 찾을 수 없습니다."))
}

/// x86_64 rel32 의 목적지 (변위가 `disp_off` 에 있고 다음 명령이 `next_off` 에서 시작할 때)
fn x86_rel32_target(data: &[u8], disp_off: usize, next_off: usize) -> Option<usize> {
    usize::try_from(next_off as i64 + read_i32(data, disp_off) as i64).ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct X86BannerSite {
    site: usize,
    site_end: usize,
    stores_off: usize,
    stores_len: usize,
    patched: bool,
}

fn x86_two_rsp_stores_len(b: &[u8]) -> Option<usize> {
    let (n1, _, _) = x86_rsp_store_info(b)?;
    let (n2, _, _) = x86_rsp_store_info(&b[n1..])?;
    Some(n1 + n2)
}

/// BannerWithInfo 채널 검사 자리와 보존할 두 스택 저장 명령의 위치·길이, 그리고 분기 끝(`fmt_off`).
/// - 원본: `test r64, r64; je skip; mov r64, disp(%rsp); mov r64, disp(%rsp); ... cmp $6; jne fmt; cmpl "stab"`
/// - 패치 후: `mov r64, disp(%rsp); mov r64, disp(%rsp); lea chan(%rip), %rcx; mov $len, %edx; jmp fmt; nop...`
fn find_banner_site_x86(ctx: &BinaryContext) -> Result<X86BannerSite, String> {
    ctx.resolve_in_funcs(
        &["render.BannerWithInfo"],
        "cli/render/product_name.go",
        "BannerWithInfo 채널 검사",
        |start, end| {
            let body = &ctx.data[start..end];
            let mut matches = Vec::new();
            let mut i = 0usize;
            while i + 28 <= body.len() {
                // 1) 원본 형태 ("stable" 6글자 + "stab" 리터럴 검사 블록의 jne 목적지까지 동적 측정)
                if matches!(body[i], 0x48 | 0x4d) && body[i + 1] == 0x85 && (0xc0..=0xff).contains(&body[i + 2]) {
                    let je_pos = skip_x86_nops(body, i + 3);
                    if let Some((4, je_next, _)) = x86_jcc_target(body, je_pos) {
                        let stores_rel = skip_x86_nops(body, je_next);
                        if let Some(stores_len) = body.get(stores_rel..).and_then(x86_two_rsp_stores_len) {
                            let after_stores = stores_rel + stores_len;
                            let search_end = (after_stores + 24).min(body.len());
                            let mut fmt_found = None;
                            for k in after_stores..search_end {
                                if let Some((cmp_len, 6)) = x86_cmp_imm8(&body[k..]) {
                                    let jne_pos = skip_x86_nops(body, k + cmp_len);
                                    if let Some((5, jne_next, fmt_rel)) = x86_jcc_target(body, jne_pos) {
                                        if fmt_rel > jne_next
                                            && fmt_rel <= body.len()
                                            && fmt_rel >= i + stores_len + 17
                                            && find_subslice(&body[jne_next..fmt_rel], b"stab").is_some()
                                        {
                                            fmt_found = Some(fmt_rel);
                                            break;
                                        }
                                    }
                                }
                            }
                            if let Some(fmt_rel) = fmt_found {
                                matches.push(X86BannerSite {
                                    site: start + i,
                                    site_end: start + fmt_rel,
                                    stores_off: stores_rel - i,
                                    stores_len,
                                    patched: false,
                                });
                                i += 1;
                                continue;
                            }
                        }
                    }
                }
                // 2) 이미 패치된 형태 (두 스택 저장 + lea %rcx + mov $len,%edx + jmp rel32 + nop 패딩)
                if let Some(stores_len) = x86_two_rsp_stores_len(&body[i..]) {
                    let lea_rel = i + stores_len;
                    if lea_rel + 17 <= body.len()
                        && body[lea_rel..lea_rel + 3] == [0x48, 0x8d, 0x0d]
                        && body[lea_rel + 7] == 0xba
                        && (1..=64).contains(&read_u32(body, lea_rel + 8))
                        && body[lea_rel + 12] == 0xe9
                    {
                        let rel_skip = read_i32(body, lea_rel + 13);
                        let jmp_next = lea_rel + 17;
                        if (0..=128).contains(&rel_skip) {
                            let end_rel = jmp_next + rel_skip as usize;
                            let target_is_chan = ctx
                                .x86_lea_target_off(start + lea_rel)
                                .and_then(|(_, p)| ctx.data.get(p..))
                                .is_some_and(|s| s.starts_with(b"patch v"));
                            if end_rel <= body.len()
                                && body[jmp_next..end_rel].iter().all(|&b| b == 0x90)
                                && (target_is_chan || rel_skip >= 4)
                            {
                                matches.push(X86BannerSite {
                                    site: start + i,
                                    site_end: start + end_rel,
                                    stores_off: 0,
                                    stores_len,
                                    patched: true,
                                });
                                // 패치 끝의 0x90 패딩과 그 직후 코드에서 겹쳐 잡히지 않게 건너뛴다
                                i = end_rel.max(i + 1);
                                continue;
                            }
                        }
                    }
                }
                i += 1;
            }
            // `.gopclntab` 없는 합성 단위 테스트(뒷부분을 더미 바이트로 채운 55바이트 고정 레이아웃) 호환 폴백
            if matches.is_empty() && ctx.pcln.is_none() {
                for k in 0..body.len().saturating_sub(55) {
                    if body[k..k + 5] == [0x48, 0x85, 0xd2, 0x0f, 0x84] {
                        if let Some(stores_len) = body.get(k + 9..).and_then(x86_two_rsp_stores_len) {
                            matches.push(X86BannerSite {
                                site: start + k,
                                site_end: start + k + 55,
                                stores_off: 9,
                                stores_len,
                                patched: false,
                            });
                        }
                    }
                }
            }
            matches
        },
    )
}

/// 이미 패치된 banner 가 쓰는 동굴과 기존 채널 문자열의 끝. lea 가 가리키는 채널 문자열 자리에서 구한다.
fn banner_cave_x86(ctx: &BinaryContext) -> Result<Option<(usize, usize)>, String> {
    let Ok(bs) = find_banner_site_x86(ctx) else {
        return Ok(None);
    };
    if !bs.patched {
        return Ok(None);
    }
    let lea_off = bs.site + bs.stores_len;
    let len = read_u32(ctx.data, lea_off + 8) as usize; // mov $len,%edx
    ctx.x86_lea_target_off(lea_off)
        .map(|(_, p)| p)
        .filter(|&p| ctx.data.get(p..).is_some_and(|s| s.starts_with(b"patch v")))
        .and_then(|p| Some((p.checked_sub(CAVE_CHAN_OFF)?, p + len)))
        .map(Some)
        .ok_or_else(|| "BannerWithInfo 기존 패치가 가리키는 채널 문자열(\"patch v…\")을 찾을 수 없습니다.".into())
}

/// x86_64 patch-info 트램펄린(`lea info(%rip),%r8; mov $len,%r9d; jmp concatstring3`)이면 `(본문 오프셋, 트램펄린 끝)` 반환
fn decode_x86_info_tramp(ctx: &BinaryContext, tramp: usize, concat3: usize) -> Option<(usize, usize)> {
    let d = ctx.data;
    let w = d.get(tramp..tramp + 18)?;
    if w[0..3] != [0x4c, 0x8d, 0x05] || w[7..9] != [0x41, 0xb9] || w[13] != 0xe9 {
        return None;
    }
    if x86_rel32_target(d, tramp + 14, tramp + 18) != Some(concat3) {
        return None;
    }
    let info_off = x86_rel32_target(d, tramp + 3, tramp + 7)?;
    (info_off >= CAVE_INFO_OFF && d.get(info_off..).is_some_and(|s| s.starts_with(b"\n\n")))
        .then_some((info_off, tramp + 18))
}

/// BuildHeader 끝의 `"\n" + strings.Join(lines, "\n")` concatstring2 호출 자리 (패치 후엔 트램펄린 호출).
/// `.gopclntab`에서 `strings.Join` 호출이 보이면 그 직후(≤64바이트) 이어지는 `concatstring2`/트램펄린 호출을 고르고,
/// 합성 테스트처럼 `strings.Join`이 없으면 인자 준비 시퀀스가 앞선 `concatstring2`/트램펄린 호출을 고른다.
fn find_build_header_call_x86(ctx: &BinaryContext) -> Result<usize, String> {
    let (concat2, _) = ctx.get_func("runtime.concatstring2")?;
    let concat3 = ctx.get_func("runtime.concatstring3").ok().map(|(s, _)| s);
    let is_target_call = |call_abs: usize| -> bool {
        let Some(dest) = ctx.x86_call_target_off(call_abs) else {
            return false;
        };
        dest == concat2 || concat3.and_then(|c3| decode_x86_info_tramp(ctx, dest, c3)).is_some()
    };
    ctx.resolve_in_funcs(
        &["render.BuildHeader"],
        "cli/render/header.go",
        "BuildHeader concatstring2",
        |start, end| {
            let body = &ctx.data[start..end];
            let join_calls: Vec<usize> = (0..body.len().saturating_sub(5))
                .filter(|&p| ctx.call_target_symbol(start + p) == Some("strings.Join"))
                .collect();
            if !join_calls.is_empty() {
                return (0..body.len().saturating_sub(5))
                    .filter(|&p| {
                        is_target_call(start + p)
                            && join_calls.iter().any(|&jp| p > jp && p - jp <= 64)
                    })
                    .map(|p| start + p)
                    .collect();
            }
            // strings.Join 심볼이 없는 합성 테스트 폴백: 고정 오프셋 없이 앞 32바이트 내 인자 세팅 확인
            (0..body.len().saturating_sub(5))
                .filter(|&p| {
                    let win = &body[p.saturating_sub(32)..p];
                    (is_target_call(start + p) || ctx.pcln.is_none() && body[p] == 0xe8)
                        && find_subslice(win, &[0x48, 0x89, 0xc7]).is_some()
                        && find_subslice(win, &[0x48, 0x8d, 0x1d]).is_some()
                })
                .map(|p| start + p)
                .collect()
        },
    )
}

/// 이미 패치된 patch-info 가 쓰는 동굴과 기존 트램펄린의 끝.
fn patch_info_cave_x86(ctx: &BinaryContext) -> Result<Option<(usize, usize)>, String> {
    let call = find_build_header_call_x86(ctx)?;
    let (concat2, _) = ctx.get_func("runtime.concatstring2")?;
    let (concat3, _) = ctx.get_func("runtime.concatstring3")?;
    let tramp = ctx.x86_call_target_off(call);
    if tramp == Some(concat2) {
        return Ok(None);
    }
    tramp
        .and_then(|t| decode_x86_info_tramp(ctx, t, concat3))
        .map(|(n, end)| Some((n - CAVE_INFO_OFF, end)))
        .ok_or_else(|| "BuildHeader 가 concatstring2 도, 알아볼 수 있는 패치 정보 트램펄린도 부르지 않습니다.".into())
}

/// banner(채널 문자열) / patch-info(패치 정보 + 트램펄린) 몫
#[derive(Clone, Copy, PartialEq)]
enum CavePart {
    Chan,
    Info,
}

impl CavePart {
    /// 고정 배치에서 동굴 기준 자기 몫
    fn range(self) -> std::ops::Range<usize> {
        match self {
            CavePart::Chan => CAVE_CHAN_OFF..CAVE_INFO_OFF,
            CavePart::Info => CAVE_INFO_OFF..CAVE_MIN,
        }
    }
}

/// `from` 부터 이어지는 0xcc 의 끝
fn cc_run_end(data: &[u8], from: usize) -> usize {
    from + data.get(from..).map_or(0, |s| s.iter().take_while(|&&b| b == 0xcc).count())
}

/// 코드 섹션(`.text` / `__text`) 안의 0xcc 구간 [시작, 끝), 파일 순서 (16바이트 이상만).
/// 같은 실행 세그먼트에 .rodata·__go_type 같은 데이터도 있어서, 함수 사이 패딩만 보도록 코드 섹션으로 좁힌다.
/// Go 함수 표 범위보다 넓게 잡는 이유: 1.5.14 linux_x64 의 쓸 만한 패딩(877바이트)은 Go 코드 뒤,
/// 함께 링크된 C 코드 사이에서 페이지 경계까지 채운 0xcc 다.
fn code_cc_runs(ctx: &BinaryContext) -> Result<Vec<(usize, usize)>, String> {
    let (lo, hi) = ctx.text_section.unwrap_or((0, ctx.data.len()));
    let hi = hi.min(ctx.data.len());
    let d = &ctx.data[..hi];
    let mut runs = Vec::new();
    let mut i = lo;
    while i < hi {
        if d[i] != 0xcc {
            i += 1;
            continue;
        }
        let e = cc_run_end(d, i);
        if e - i >= 16 {
            runs.push((i, e));
        }
        i = e;
    }
    Ok(runs)
}

/// x86_64 banner / patch-info 가 쓸 자리를 고른다. 반환: (동굴 기준점, 자기 몫을 쓸 수 있는 끝)
/// 1. 자기 패치가 이미 쓴 자리(`own` = 동굴, 그때 쓴 내용의 끝): 그 뒤로 이어지는 0xcc 까지, 고정 배치 몫을 넘지 않게.
/// 2. 다른 패치가 쓴 동굴(`other` = 동굴, 그 패치 내용의 끝)에 자기 몫이 0xcc 로 비어 있으면 그 동굴 (고정 배치).
///    패치마다 새 동굴을 찾으면 0xcc 패딩이 한 곳뿐인 버전(1.5.9·1.5.10·1.5.12)에서 재패치가 실패한다.
/// 3. 새 1024바이트 0xcc 동굴 (고정 배치: 채널 +0, 패치 정보 +64).
/// 4. 그런 동굴이 없으면(1.5.14 linux_x64) 대체 배치: 함수 사이 0xcc 구간을 따로 쓴다.
///    채널은 32~255바이트 구간 중 첫째, 패치 정보는 256바이트 이상 중 가장 긴 것 — 크기대가 달라 서로의 구간을
///    고르지 않고, 원본 바이트만 보고 각자 골라도 겹치지 않는다. 다른 패치 내용 바로 뒤에 남은 0xcc 꼬리는
///    고르지 않아 적용 순서와 상관없이 같은 자리가 되고 그 패치의 재패치 여유도 줄지 않는다.
///    배치가 다른 옛 패치본을 만나도 0xcc 만 쓴다.
///    동굴 기준점은 자기 문자열 위치에서 고정 배치 오프셋을 뺀 값이라 재패치 때 같은 식으로 되찾는다.
fn pick_cave_x86(
    ctx: &BinaryContext,
    part: CavePart,
    own: Option<(usize, usize)>,
    other: Option<(usize, usize)>,
) -> Result<(usize, usize), String> {
    let r = part.range();
    if let Some((cave, content_end)) = own {
        return Ok((cave, (cave + r.end).min(cc_run_end(ctx.data, content_end).max(content_end))));
    }
    let free = |cave: usize| {
        ctx.data
            .get(cave + r.start..cave + r.end)
            .is_some_and(|s| s.iter().all(|&b| b == 0xcc))
    };
    match other {
        Some((cave, _)) if free(cave) => return Ok((cave, cave + r.end)),
        None => {
            if let Ok(cave) = find_cave(ctx) {
                return Ok((cave, cave + r.end));
            }
        }
        Some(_) => {}
    }
    let other_tail = other.map(|(_, end)| end);
    let runs: Vec<_> = code_cc_runs(ctx)?.into_iter().filter(|&(s, _)| Some(s) != other_tail).collect();
    let pick = match part {
        CavePart::Chan => runs.iter().find(|&&(s, e)| (32..256).contains(&(e - s))).copied(),
        CavePart::Info => runs.iter().filter(|&&(s, e)| e - s >= 256).max_by_key(|&&(s, e)| e - s).copied(),
    };
    pick.and_then(|(s, e)| Some((s.checked_sub(r.start)?, e)))
        .ok_or_else(|| format!("실행 파일 내 0xcc 여유 공간({CAVE_MIN}바이트, 또는 따로 쓸 구간)을 찾을 수 없습니다."))
}

/// Mach-O ARM64: `__TEXT` 세그먼트(r-x) 안, 마지막 섹션 뒤의 페이지 정렬 패딩을 동굴로 쓴다.
/// 섹션 헤더로 위치를 정하므로 패치 후 내용이 바뀌어도 같은 자리를 돌려준다(재패치 가능).
/// Linux ELF ARM64 는 실행 세그먼트 바로 뒤에 RW 세그먼트가 붙어 있어 쓸 수 있는 패딩이 없다.
fn find_cave_a64(ctx: &BinaryContext) -> Result<usize, String> {
    if ctx.format != Format::MachO64 {
        return Err("ARM64 banner/patch-info 패치는 macOS(Mach-O)에서만 지원됩니다 (Linux ARM64 는 여유 공간 없음).".into());
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
///   ldp xP, xL, [xBase, #..]; cbz xL, skip
///   str x1, [sp, #..]; str x0, [sp, #..]; cmp xL, #6; b.ne fmt   ("stable" 검사)
/// 패치 후:
///   adrp xP, chan; add xP, xP, #lo; (str 두 줄 유지); movz xL, #len; b fmt
/// 두 str 는 Sprintf 뒤 concatstring2 가 다시 읽는 제품명 슬롯이므로 반드시 남긴다(x86 과 같은 이유).
fn resolve_banner_a64(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    let cave = find_cave_a64(ctx)?;
    let chan = format!("patch v{}", env!("CARGO_PKG_VERSION")).into_bytes();
    assert!(chan.len() <= CAVE_INFO_OFF - CAVE_CHAN_OFF);
    let chan_off = cave + CAVE_CHAN_OFF;
    let chan_va = a64_va(ctx, chan_off)?;

    let d = ctx.data;
    let is_str_sp = |w: u32| w & 0xffc0_03e0 == 0xf900_03e0;
    let (site, p, l, fmt_off) = ctx.resolve_in_funcs(
        &["render.BannerWithInfo"],
        "cli/render/product_name.go",
        "BannerWithInfo ARM64 채널 검사",
        |start, end| {
            let mut matches = Vec::new();
            let mut off = start;
            while off + 24 <= end {
                let w = |k: usize| word(d, off + k * 4);
                if !(is_str_sp(w(2)) && is_str_sp(w(3))) {
                    off += 4;
                    continue;
                }
                let (w0, w1, w4, w5) = (w(0), w(1), w(4), w(5));
                // 원본 형태 (프레임 크기에 따른 앞쪽 x27 설정 유무에 의존하지 않는다)
                if w0 & 0xffc0_0000 == 0xa940_0000 && a64::bcond(w5) == Some(a64::COND_NE) {
                    let (p, l) = (w0 & 31, (w0 >> 10) & 31);
                    if p != l && w1 & 0xff00_001f == 0xb400_0000 | l && w4 == 0xf100_181f | (l << 5) {
                        matches.push((off, p, l, a64::bcond_target(w5, off + 20)));
                    }
                }
                // 이미 패치된 형태 (`"patch v"` 문자열 VA 역추적으로 확인)
                if let Some((p, target_str)) = ctx.a64_adrp_add_target_off(off) {
                    let is_chan = d.get(target_str..).is_some_and(|s| s.starts_with(b"patch v"));
                    if is_chan && a64::is_movz(w4) && a64::is_b(w5) {
                        if let Some(target_off) = ctx
                            .off_to_va(off + 20)
                            .map(|pc| a64::branch26_target(w5, pc))
                            .and_then(|t| ctx.va_to_off(t))
                        {
                            matches.push((off, p, a64::rd(w4), target_off));
                        }
                    }
                }
                off += 4;
            }
            matches
        },
    )?;
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
/// 동굴 트램펄린으로 돌려 세 번째 인자(적용 패치 정보)를 붙인 concatstring3 로 꼬리 분기한다.
fn resolve_patch_info_a64(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    let (concat2_start, _) = ctx.get_func("runtime.concatstring2")?;
    let (concat3_start, _) = ctx.get_func("runtime.concatstring3")?;
    let cave = find_cave_a64(ctx)?;

    let info = format!("\n\n{}", patch_info_text(ctx)).into_bytes();
    if info.len() > 0xffff {
        return Err("패치 정보 문자열이 너무 깁니다.".into());
    }
    let info_off = cave + CAVE_INFO_OFF;
    let tramp_off = (info_off + info.len() + 15) & !15;
    if tramp_off + 24 > cave + CAVE_MIN {
        return Err("패치 정보 문자열이 여유 공간을 초과합니다.".into());
    }
    let info_va = a64_va(ctx, info_off)?;
    let tramp_va = a64_va(ctx, tramp_off)?;
    let c3_va = a64_va(ctx, concat3_start)?;
    let tramp = words(&[
        a64::adrp(5, tramp_va, info_va)?,
        a64::add_imm(5, 5, info_va & 0xfff),
        a64::movz(6, info.len() as u32),
        a64::adrp(a64::X16, tramp_va + 12, c3_va)?,
        a64::add_imm(a64::X16, a64::X16, c3_va & 0xfff),
        a64::BR_X16,
    ]);

    let d = ctx.data;
    let is_target_bl = |bl_off: usize| -> bool {
        let Some(target_off) = ctx.a64_bl_target_off(bl_off) else {
            return false;
        };
        target_off == concat2_start || (cave..cave + CAVE_MIN).contains(&target_off)
    };
    let call = ctx.resolve_in_funcs(
        &["render.BuildHeader"],
        "cli/render/header.go",
        "BuildHeader ARM64 concatstring2",
        |bh_start, bh_end| {
            let join_calls: Vec<usize> = (bh_start..bh_end.saturating_sub(3))
                .step_by(4)
                .filter(|&p| ctx.call_target_symbol(p) == Some("strings.Join"))
                .collect();
            if !join_calls.is_empty() {
                return (bh_start..bh_end.saturating_sub(3))
                    .step_by(4)
                    .filter(|&p| {
                        is_target_bl(p) && join_calls.iter().any(|&jp| p > jp && p - jp <= 64)
                    })
                    .collect();
            }
            // strings.Join 심볼이 없는 합성 테스트 폴백: 앞 8워드 내 인자 세팅 확인
            (bh_start..bh_end.saturating_sub(3))
                .step_by(4)
                .filter(|&p| {
                    if !is_target_bl(p) {
                        return false;
                    }
                    let lo = p.saturating_sub(32).max(bh_start);
                    let has_len1 = (lo..p).step_by(4).any(|q| matches!(word(d, q), 0xb240_03e2 | 0xd280_0022));
                    let has_adrp1 = (lo..p).step_by(4).any(|q| a64::is_adrp(word(d, q)) && a64::rd(word(d, q)) == 1);
                    has_len1 && has_adrp1
                })
                .collect()
        },
    )?;
    Ok(vec![
        ByteEdit { offset: info_off, payload: info },
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
            // 제품명 옆 괄호 안에 표시: "Antigravity CLI 1.5.7 (patch v0.3.0)"
            let chan = format!("patch v{}", env!("CARGO_PKG_VERSION")).into_bytes();
            assert!(chan.len() <= CAVE_INFO_OFF - CAVE_CHAN_OFF);

            // BannerWithInfo 패치: 빈 채널 대신 주입된 채널 문자열 포맷 루틴 활성화.
            // 패치된 형태도 받아 패치본을 다시 패치할 수 있게 한다 (두 저장 명령의 위치·길이와 분기 끝을 동적으로 유지).
            let bs = find_banner_site_x86(ctx)?;
            let chan_site = bs.site;
            let chan_site_end = bs.site_end;
            let site_len = chan_site_end - chan_site;
            let own = banner_cave_x86(ctx)?;
            let (cave, limit) = pick_cave_x86(
                ctx,
                CavePart::Chan,
                own,
                patch_info_cave_x86(ctx).ok().flatten(),
            )?;
            let chan_off = cave + CAVE_CHAN_OFF;
            if chan_off + chan.len() > limit {
                return Err("채널 문자열이 0xcc 여유 공간을 초과합니다.".into());
            }
            // 기존 문자열이 더 길었으면 남는 꼬리를 0xcc 로 되돌린다 (다음 재패치 때 쓸 자리를 줄이지 않게)
            let mut chan_payload = chan.clone();
            if let Some((_, old_end)) = own {
                chan_payload.resize(chan.len().max(old_end.saturating_sub(chan_off)), 0xcc);
            }
            let mut edits = vec![ByteEdit {
                offset: chan_off,
                payload: chan_payload,
            }];

            // 원본은 채널 분기 진입 시 제품명 문자열(rax=ptr, rbx=len)을 스택 슬롯에 저장하고,
            // Sprintf 이후 그 슬롯을 다시 읽어 concatstring2 로 이어 붙인다.
            // 이 두 저장을 건너뛰면 초기화되지 않은 슬롯을 이어 붙이다 SIGSEGV 가 나므로 그대로 보존한다.
            let stores = chan_site + bs.stores_off;
            let mut chan_patch = ctx.data[stores..stores + bs.stores_len].to_vec();
            let pc = chan_site + chan_patch.len() + 7;
            let disp_chan = (chan_off as i64) - (pc as i64);
            chan_patch.extend_from_slice(&[0x48, 0x8d, 0x0d]);
            chan_patch.extend_from_slice(&(disp_chan as i32).to_le_bytes());

            chan_patch.push(0xba);
            chan_patch.extend_from_slice(&(chan.len() as u32).to_le_bytes());

            let pc = chan_site + chan_patch.len() + 5;
            let rel_skip = (chan_site_end as i64) - (pc as i64);
            chan_patch.push(0xe9);
            chan_patch.extend_from_slice(&(rel_skip as i32).to_le_bytes());

            while chan_patch.len() < site_len {
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

/// 상단 배너 아래에 주입할 적용 패치 요약 본문.
/// `ctx.selected_patches`가 비어 있으면(가용성 사전 검사 등) 전체 패치 기준으로 생성해 여유 공간을 검증한다.
fn patch_info_text(ctx: &BinaryContext) -> String {
    let ids: Vec<&'static str> = if ctx.selected_patches.is_empty() {
        PATCH_REGISTRY
            .iter()
            .map(|p| p.id)
            .filter(|&id| id != "patch-info")
            .collect()
    } else {
        ctx.selected_patches
            .iter()
            .copied()
            .filter(|&id| id != "patch-info")
            .collect()
    };

    let has = |id: &str| ids.contains(&id);
    let simple: Vec<&str> = PATCH_REGISTRY
        .iter()
        .map(|p| p.id)
        .filter(|&id| {
            !matches!(id, "patch-info" | "banner" | "code-theme" | "compact")
                && tier_index(id).is_none()
                && has(id)
        })
        .collect();

    let row = |label: &str, val: String| format!(" \x1b[90m│ {label:<10}\x1b[0m  {val}");
    let mut lines: Vec<String> = Vec::new();
    let mut has_feature = false;

    if !has("banner") {
        lines.push(row("patch", format!("\x1b[36mv{}\x1b[0m", env!("CARGO_PKG_VERSION"))));
    }
    if !simple.is_empty() {
        lines.push(row("patches", simple.join("\x1b[90m · \x1b[0m")));
        has_feature = true;
    }
    match (has("code-theme"), has("compact")) {
        (true, true) => {
            let short = format_compact_tokens(ctx.compact_tokens);
            lines.push(row(
                "theme",
                format!(
                    "\x1b[36m{}\x1b[0m  \x1b[90m·  compact\x1b[0m \x1b[36m{short}\x1b[0m",
                    ctx.code_theme
                ),
            ));
            has_feature = true;
        }
        (true, false) => {
            lines.push(row("theme", format!("\x1b[36m{}\x1b[0m", ctx.code_theme)));
            has_feature = true;
        }
        (false, true) => {
            let short = format_compact_tokens(ctx.compact_tokens);
            lines.push(row("compact", format!("\x1b[36m{short}\x1b[0m")));
            has_feature = true;
        }
        (false, false) => {}
    }
    for (ti, spec) in TIERS.iter().enumerate() {
        if has(spec.id) {
            lines.push(row(spec.key, format!("\x1b[36m{}\x1b[0m", ctx.tier_models[ti])));
            has_feature = true;
        }
    }
    if !has_feature {
        lines.push(row("patches", "\x1b[90mnone\x1b[0m".to_string()));
    }
    lines.join("\n")
}

fn resolve_patch_info(ctx: &BinaryContext) -> Result<Vec<ByteEdit>, String> {
    match ctx.arch {
        Arch::X86_64 => {
            // BuildHeader 패치: concatstring2 호출을 트램펄린(concatstring3) 호출로 변경.
            // 이미 패치된 바이너리면 그때 쓴 동굴을 다시 쓴다.
            let call_site = find_build_header_call_x86(ctx)?;
            let (concat3_start, _) = ctx.get_func("runtime.concatstring3")?;
            let own = patch_info_cave_x86(ctx)?;
            let (cave_offset, limit) = pick_cave_x86(
                ctx,
                CavePart::Info,
                own,
                banner_cave_x86(ctx).ok().flatten(),
            )?;

            let info = format!("\n\n{}", patch_info_text(ctx)).into_bytes();

            let info_va = cave_offset + CAVE_INFO_OFF;
            let info_len = info.len();
            let tramp_va = (info_va + info_len + 15) & !15;

            // 트램펄린 루틴 생성:
            // lea info(%rip), %r8
            // mov $info_len, %r9d
            // jmp concatstring3   (tail call)
            //
            // call 이 아니라 jmp 여야 한다. call 로 들어가면 concatstring3 의 리턴 주소가
            // pclntab 에 없는 동굴(cave)을 가리켜 GC/스택 확장 시 Go 언와인더가 실패하고,
            // morestack 경로의 레지스터 인자 스필(SP+8~)이 트램펄린의 리턴 주소를 덮어쓴다.
            // tail jmp 면 BuildHeader 가 concatstring3 를 직접 호출한 것과 동일한 프레임이 된다
            // (BuildHeader 의 outgoing 인자 영역은 7워드 스필을 충분히 수용함).
            let mut tramp = Vec::new();
            let pc = tramp_va + 7;
            let disp = (info_va as i64) - (pc as i64);
            tramp.extend_from_slice(&[0x4c, 0x8d, 0x05]);
            tramp.extend_from_slice(&(disp as i32).to_le_bytes());

            tramp.extend_from_slice(&[0x41, 0xb9]);
            tramp.extend_from_slice(&(info_len as u32).to_le_bytes());

            let pc = tramp_va + tramp.len() + 5;
            let rel_c3 = (concat3_start as i64) - (pc as i64);
            tramp.push(0xe9);
            tramp.extend_from_slice(&(rel_c3 as i32).to_le_bytes());

            if tramp_va + tramp.len() > limit {
                return Err("패치 정보 문자열이 0xcc 여유 공간을 초과합니다.".into());
            }

            // 본문과 트램펄린 사이, 그리고 기존 트램펄린이 더 뒤에 있었으면 그 자리까지 0xcc 로 채운다
            let mut info = info;
            info.resize(tramp_va - info_va, 0xcc);
            if let Some((_, old_end)) = own {
                tramp.resize(tramp.len().max(old_end.saturating_sub(tramp_va)), 0xcc);
            }
            let mut edits = vec![
                ByteEdit {
                    offset: info_va,
                    payload: info,
                },
                ByteEdit {
                    offset: tramp_va,
                    payload: tramp,
                },
            ];

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
        Arch::Arm64 => resolve_patch_info_a64(ctx),
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
        id: "pro-tier",
        title: "서브에이전트 pro 티어 모델 고정 (Pro Tier Model)",
        description: "invoke_subagent 등에서 'pro' 티어가 서버 지정 모델 대신 고른 모델(기본 gemini-4-carbon-high)로 실행되도록 고정 (기본 꺼짐)",
        symbol: "modelutils.modelIDForTier",
        default_on: false,
        resolver: resolve_pro_tier,
    },
    PatchSpec {
        id: "flash-tier",
        title: "서브에이전트 flash 티어 모델 고정 (Flash Tier Model)",
        description: "'flash' 티어를 고른 모델(기본 gemini-4-neon-medium)로 고정. flash_lite 가 없을 때 agy 유틸리티 작업도 이 티어를 씀 (기본 꺼짐)",
        symbol: "modelutils.modelIDForTier",
        default_on: false,
        resolver: resolve_flash_tier,
    },
    PatchSpec {
        id: "flash-lite-tier",
        title: "서브에이전트 flash_lite 티어 모델 고정 (Flash-Lite Tier Model)",
        description: "'flash_lite' 티어를 고른 모델(기본 gemini-4-hydrogen-low)로 고정. agy 유틸리티 작업도 이 티어를 먼저 씀 (기본 꺼짐)",
        symbol: "modelutils.modelIDForTier",
        default_on: false,
        resolver: resolve_flash_lite_tier,
    },
    PatchSpec {
        id: "banner",
        title: "제품명 옆 패치 버전 표시 (Patch Version Tag)",
        description: "상단 'Antigravity CLI 1.5.7' 옆에 '(patch v0.3.0)' 형태로 패치 버전 표시",
        symbol: "render.BannerWithInfo",
        default_on: true,
        resolver: resolve_banner,
    },
    PatchSpec {
        id: "patch-info",
        title: "상단 배너 적용 패치 정보 표시 (Patch Info)",
        description: "로고 아래에 적용된 패치 목록과 모델 티어·컴팩션·코드 테마 설정 표시 (기본 꺼짐, -p 로 명시해야 적용)",
        symbol: "render.BuildHeader",
        default_on: false,
        resolver: resolve_patch_info,
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

const VERSION_UNKNOWN: &str = "확인 불가";

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
        .unwrap_or_else(|| VERSION_UNKNOWN.to_string())
}

/// `--in-place` 백업을 대상 바이너리로 새로 써야 하는지 판정한다.
/// 패치본은 언제나 백업에서 만들어지므로 백업과 버전이 같다. 버전이 달라졌다면 agy 자체 업데이트가
/// 대상을 새 릴리즈 원본으로 바꾼 것이다. 패치 자리 하나(nodrip)만 보고 판정하면 nodrip 을 뺀 조합으로
/// in-place 한 패치본을 원본으로 오인해 하나뿐인 원본 백업을 덮어쓴다.
/// 버전을 알 수 없으면 백업을 지키는 쪽으로 갱신하지 않는다.
fn should_refresh_backup(target_version: &str, backup_version: &str, target_cut_unpatched: bool) -> bool {
    target_cut_unpatched
        && target_version != VERSION_UNKNOWN
        && backup_version != VERSION_UNKNOWN
        && target_version != backup_version
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

/// 대화형 설정의 결과
struct WizardResult {
    patches: Vec<&'static PatchSpec>,
    out_name: String,
    in_place: bool,
    args: PatchArgs,
}

/// 대화형 화면에서 -/+ 로 추천값을 고르거나 e 로 직접 입력하는 문자열 값 (code-theme 테마, *-tier 모델 ID)
struct TextParam {
    id: &'static str,
    /// 알림 문구에 쓰는 이름 ("코드 블록 테마: vs", "코드 블록 테마가 'vs'(으)로 …")
    label: &'static str,
    subject: &'static str,
    /// 하단 키 안내에서 -/+ 의 설명
    hint: &'static str,
    presets: Vec<&'static str>,
    max_len: usize,
    /// 입력값을 정규화하고 바이너리에 해당 문자열이 있는지까지 확인한다
    validate: fn(&BinaryContext, &str) -> Result<String, String>,
    value: String,
    editing: bool,
    buf: Vec<char>,
    pos: usize,
}

fn validate_code_theme(ctx: &BinaryContext, raw: &str) -> Result<String, String> {
    let theme = parse_code_theme(raw)?;
    find_chroma_theme_offset(ctx.data, &theme)?;
    Ok(theme)
}

fn validate_model_id(ctx: &BinaryContext, raw: &str) -> Result<String, String> {
    let model = parse_model_id(raw)?;
    find_model_id_offset(ctx, &model)?;
    Ok(model)
}

struct Wizard<'a> {
    src_bin: &'a Path,
    target_bin: &'a Path,
    bin_dir: &'a Path,
    ctx: &'a BinaryContext<'a>,
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
    texts: Vec<TextParam>,
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
        Key::Char(c) if !c.is_control() && buf.len() < max_len => {
            buf.insert(*pos, *c);
            *pos += 1;
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
    fn new(src_bin: &'a Path, target_bin: &'a Path, bin_dir: &'a Path, version: &'a str, ctx: &'a BinaryContext<'a>) -> Self {
        // 티어 고정 패치에 고를 모델 ID (바이너리에 문자열로 들어 있는 것만)
        let model_presets = available_model_ids(ctx);
        let avail: Vec<Result<(), String>> = PATCH_REGISTRY
            .iter()
            .map(|p| {
                let r = (p.resolver)(ctx).map(|_| ());
                match tier_index(p.id) {
                    // 기본 모델이 이 바이너리에 없어도 고를 모델이 있으면 줄은 쓸 수 있다 (켤 때 값을 검사한다)
                    Some(ti)
                        if r.is_err()
                            && !model_presets.is_empty()
                            && tier_site_found(ctx, TIERS[ti].tier) =>
                    {
                        Ok(())
                    }
                    _ => r,
                }
            })
            .collect();
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
            ctx,
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
            texts: std::iter::once(TextParam {
                    id: "code-theme",
                    label: "코드 블록 테마",
                    subject: "코드 블록 테마가",
                    hint: "테마",
                    presets: CODE_THEME_PRESETS.to_vec(),
                    max_len: 32,
                    validate: validate_code_theme,
                    value: detect_patched_code_theme(ctx).unwrap_or_else(|| ctx.code_theme.clone()),
                    editing: false,
                    buf: Vec::new(),
                    pos: 0,
                })
            .chain(TIERS.iter().enumerate().map(|(ti, t)| TextParam {
                id: t.id,
                label: t.label,
                subject: t.subject,
                hint: "모델",
                presets: model_presets.clone(),
                max_len: 64,
                validate: validate_model_id,
                value: detect_patched_tier(ctx, ti).unwrap_or_else(|| ctx.tier_models[ti].clone()),
                editing: false,
                buf: Vec::new(),
                pos: 0,
            }))
            .collect(),
        }
    }

    /// 티어 고정 줄은 고른 모델 ID 가 이 바이너리에 있어야 켤 수 있다 (기본 모델이 없는 옛 버전 대비)
    fn tier_ready(&self, i: usize) -> Result<(), String> {
        let Some(t) = self.text_param(PATCH_REGISTRY[i].id).filter(|t| tier_index(t.id).is_some()) else {
            return Ok(());
        };
        if t.presets.contains(&t.value.as_str()) {
            return Ok(());
        }
        (t.validate)(self.ctx, &t.value)
            .map(|_| ())
            .map_err(|e| format!("{e}. -/+ 로 고르거나 e 로 입력하세요."))
    }

    fn text_param(&self, id: &str) -> Option<&TextParam> {
        self.texts.iter().find(|t| t.id == id)
    }

    fn text_value(&self, id: &str) -> Option<String> {
        self.text_param(id).map(|t| t.value.clone())
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
        if !self.selected[i] {
            if let Err(e) = self.tier_ready(i) {
                self.flash = Some((S_WARN, e));
                return;
            }
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
        let avail_idx: Vec<usize> = (0..PATCH_REGISTRY.len())
            .filter(|&i| self.avail[i].is_ok() && (self.selected[i] || self.tier_ready(i).is_ok()))
            .collect();
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

    fn adjust_text(&mut self, ti: usize, delta: isize) {
        let t = &mut self.texts[ti];
        let Some(pi) = patch_index(t.id) else {
            return;
        };
        if self.avail[pi].is_err() {
            self.flash = Some((S_WARN, format!("'{}' 패치는 이 바이너리에 적용할 수 없습니다.", t.id)));
            return;
        }
        if t.presets.is_empty() {
            return;
        }
        let len = t.presets.len() as isize;
        let cur_idx = t.presets.iter().position(|&p| p == t.value).map(|i| i as isize);
        let next_idx = match cur_idx {
            Some(i) => (i + delta).rem_euclid(len) as usize,
            None => if delta < 0 { t.presets.len() - 1 } else { 0 },
        };
        t.value = t.presets[next_idx].to_string();
        self.selected[pi] = true;
        self.flash = Some((S_ACCENT, format!("{}: {}", t.label, t.value)));
    }

    fn start_text_edit(&mut self, ti: usize) {
        if self.avail[self.cursor].is_err() {
            self.flash = Some((S_WARN, format!("'{}' 패치는 이 바이너리에 적용할 수 없습니다.", self.texts[ti].id)));
            return;
        }
        let t = &mut self.texts[ti];
        t.buf = t.value.chars().collect();
        t.pos = t.buf.len();
        t.editing = true;
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
                if let Some(ti) = self.texts.iter().position(|t| t.editing) {
                    let ctx = self.ctx;
                    let t = &mut self.texts[ti];
                    match edit_inline_buffer(&mut t.buf, &mut t.pos, t.max_len, &key) {
                        Some(false) => t.editing = false,
                        Some(true) => {
                            let raw: String = t.buf.iter().collect();
                            match (t.validate)(ctx, &raw) {
                                Ok(value) => {
                                    t.editing = false;
                                    self.flash = Some((S_OK, format!("{} '{value}'(으)로 설정되었습니다.", t.subject)));
                                    t.value = value;
                                    if let Some(pi) = patch_index(t.id) {
                                        if self.avail[pi].is_ok() {
                                            self.selected[pi] = true;
                                        }
                                    }
                                }
                                Err(err) => self.flash = Some((S_ERR, err)),
                            }
                        }
                        None => {}
                    }
                    return Action::Continue;
                }

                let on_compact = PATCH_REGISTRY.get(self.cursor).is_some_and(|p| p.id == "compact");
                let on_text = PATCH_REGISTRY
                    .get(self.cursor)
                    .and_then(|p| self.texts.iter().position(|t| t.id == p.id));
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
                    Key::Char('-') | Key::Char('[') if on_text.is_some() => self.adjust_text(on_text.unwrap_or(0), -1),
                    Key::Char('+') | Key::Char('=') | Key::Char(']') if on_text.is_some() => {
                        self.adjust_text(on_text.unwrap_or(0), 1)
                    }
                    Key::Char('e') | Key::Char('E') if on_text.is_some() => self.start_text_edit(on_text.unwrap_or(0)),
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
            } else if let Some(t) = self.text_param(p.id).filter(|_| ok) {
                line = append_inline_param(line, t.editing, &t.buf, t.pos, &t.value, self.selected[i]);
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
        let on_text = PATCH_REGISTRY.get(self.cursor).and_then(|p| self.text_param(p.id));
        let footer = if self.editing_compact || self.texts.iter().any(|t| t.editing) {
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
        } else if let Some(t) = on_text {
            vec![key_hints(&[
                ("↑↓", "이동"),
                ("space", "선택"),
                ("-/+", t.hint),
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
            } else if let Some(t) = self.text_param(p.id) {
                l = l.s(S_ACCENT, format!("  [{}]", t.value));
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
                    let in_place = wiz.out_choice == 1;
                    return Ok(Some(WizardResult {
                        patches: chosen,
                        out_name: if in_place { String::new() } else { wiz.name_str() },
                        in_place,
                        args: PatchArgs {
                            compact: Some(wiz.compact_tokens),
                            code_theme: wiz.text_value("code-theme"),
                            tiers: TIERS.map(|t| wiz.text_value(t.id)),
                        },
                    }));
                }
            }
        }
    }
}

/// 값을 받는 패치(compact / code-theme / *-tier)에 줄 값. 비어 있으면 기본값을 쓴다.
#[derive(Default, Clone, Debug, PartialEq)]
struct PatchArgs {
    compact: Option<u32>,
    code_theme: Option<String>,
    /// TIERS 순서 (pro, flash, flash_lite)
    tiers: [Option<String>; 3],
}

impl PatchArgs {
    fn is_empty(&self) -> bool {
        self.compact.is_none() && self.code_theme.is_none() && self.tiers.iter().all(Option::is_none)
    }

    /// 값을 준 패치를 선택 목록에 넣는다 (`--compact 180k` 만 줘도 compact 가 적용되도록)
    fn ensure_selected(&self, patches: &mut Vec<&'static PatchSpec>) {
        let tiers = TIERS.iter().zip(&self.tiers).map(|(t, v)| (t.id, v.is_some()));
        for (id, given) in [("compact", self.compact.is_some()), ("code-theme", self.code_theme.is_some())]
            .into_iter()
            .chain(tiers)
        {
            if given {
                ensure_patch_selected(patches, id);
            }
        }
    }

    /// `other` 에 있는 값이 우선한다
    fn overlay(&mut self, other: &PatchArgs) {
        if other.compact.is_some() {
            self.compact = other.compact;
        }
        if other.code_theme.is_some() {
            self.code_theme.clone_from(&other.code_theme);
        }
        for (mine, theirs) in self.tiers.iter_mut().zip(&other.tiers) {
            if theirs.is_some() {
                mine.clone_from(theirs);
            }
        }
    }

    fn apply_to(&self, ctx: &mut BinaryContext) {
        if let Some(tokens) = self.compact {
            ctx.compact_tokens = tokens;
        }
        if let Some(theme) = &self.code_theme {
            ctx.code_theme.clone_from(theme);
        }
        for (slot, model) in ctx.tier_models.iter_mut().zip(&self.tiers) {
            if let Some(model) = model {
                slot.clone_from(model);
            }
        }
    }
}

fn apply_inline_patch_arg(id: &str, val: Option<&str>, args: &mut PatchArgs) -> Result<(), String> {
    if let Some(raw_val) = val {
        match id {
            "compact" => args.compact = Some(parse_compact_tokens(raw_val)?),
            "code-theme" => args.code_theme = Some(parse_code_theme(raw_val)?),
            _ if tier_index(id).is_some() => args.tiers[tier_index(id).unwrap_or(0)] = Some(parse_model_id(raw_val)?),
            _ => return Err(format!("'{id}' 패치는 '=값' 인자를 지원하지 않습니다.")),
        }
    }
    Ok(())
}

fn parse_patch_list(spec_str: &str, args: &mut PatchArgs) -> Result<Vec<&'static PatchSpec>, String> {
    let items: Vec<&str> = spec_str.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    let mut out: Vec<&'static PatchSpec> = Vec::new();
    if items.is_empty() || items.contains(&"all") {
        // 'all' 은 기본 활성(default_on) 패치 전체. 기본 꺼짐 패치는 'all,patch-info' 나 'all,compact=180k' 처럼 명시한다.
        out.extend(PATCH_REGISTRY.iter().filter(|p| p.default_on));
    }
    // 'all' 과 함께 준 ID 도 하나하나 검사한다 ('all,nodirp' 같은 오타를 조용히 무시하지 않도록)
    for item in items {
        let (id, val) = item.split_once('=').map_or((item, None), |(k, rhs)| (k.trim(), Some(rhs.trim())));
        apply_inline_patch_arg(id, val, args)?;
        if id == "all" {
            continue;
        }
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
    ctx: &mut BinaryContext,
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

    ctx.selected_patches = patches.iter().map(|p| p.id).collect();
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
        } else if let Some(ti) = tier_index(spec.id) {
            println!(
                "    - [{}] {} [model = {}] ({})",
                spec.id,
                spec.title,
                ctx.tier_models[ti],
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
    ctx: &mut BinaryContext,
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
  agy-cli-patch -p all,pro-tier,flash-tier,flash-lite-tier -o agy-batch  서브에이전트 티어 고정 (pro→carbon, flash→neon, flash_lite→hydrogen)
  agy-cli-patch -p all,patch-info -o agy-batch  시작 화면 배너 아래에 적용된 패치·설정 요약 표시
  agy-cli-patch --preset                  기본 프리셋 2종(agy-batch, agy-nodrip) 일괄 생성
  agy-cli-patch -p all --in-place         원본 백업(antigravity.orig) 후 기본 agy에 직접 적용
  agy-cli-patch --restore                 antigravity.orig 백업에서 원본 복구

옵션:
  --bin <경로>              원본 antigravity 바이너리 경로 직접 지정 (미지정 시 자동 탐색)
  -p, --patches <ID>        쉼표로 구분된 패치 ID 또는 'all' (예: nodrip,batch,compact=180k,patch-info)
  --compact <토큰>          자동 컴팩션 토큰 임계값 지정 (32k~1000k, 예: 180k, 180000; 지정 시 compact 자동 활성화)
  --code-theme <테마>       terminal 스킴 코드 블록 Chroma 테마 지정 (기본: vs, 예: vs, solarized-light, bw)
  --pro-tier <모델 ID>      'pro' 티어(invoke_subagent 등)에 쓸 모델 (기본: gemini-4-carbon-high; 지정 시 pro-tier 자동 활성화)
  --flash-tier <모델 ID>    'flash' 티어에 쓸 모델 (기본: gemini-4-neon-medium; 지정 시 flash-tier 자동 활성화)
  --flash-lite-tier <모델 ID> 'flash_lite' 티어에 쓸 모델 (기본: gemini-4-hydrogen-low; 지정 시 flash-lite-tier 자동 활성화)
  -o, --output <이름>       생성할 실행 파일 이름 또는 경로
  --preset                  프롬프트 없이 agy-batch와 agy-nodrip 생성
  --in-place                원본 백업 후 기본 바이너리 덮어쓰기
  --restore                 --in-place 백업 복구
  --tiers                   바이너리에 고정된 서브에이전트 티어 표를 한 줄로 출력 (예: pro=gemini-4-carbon-high, 없으면 빈 줄)
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
    let mut tiers_mode = false;
    let mut patches_arg: Option<String> = None;
    let mut output_arg: Option<String> = None;
    let mut cli_args = PatchArgs::default();
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
            "--tiers" => tiers_mode = true,
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
                cli_args.compact = Some(parse_compact_tokens(&raw)?);
            }
            "--code-theme" => {
                let raw = args.next().ok_or("--code-theme 옵션에 테마 이름(예: vs, solarized-light, bw)이 필요합니다.")?;
                cli_args.code_theme = Some(parse_code_theme(&raw)?);
            }
            flag if TIERS.iter().any(|t| t.flag == flag) => {
                let ti = TIERS.iter().position(|t| t.flag == flag).unwrap_or(0);
                let raw = args
                    .next()
                    .ok_or_else(|| format!("{flag} 옵션에 모델 ID(예: {})가 필요합니다.", TIERS[ti].default_model))?;
                cli_args.tiers[ti] = Some(parse_model_id(&raw)?);
            }
            "-o" | "--output" => {
                output_arg = Some(args.next().ok_or("-o/--output 옵션에 파일명이 필요합니다.")?);
            }
            other => return Err(format!("알 수 없는 옵션: {other} (--help 참고)")),
        }
    }

    if tiers_mode {
        // 읽기 전용 질의. 실행 중인 agy 의 /proc/<pid>/exe 처럼 링크이거나 교체돼 지워진 파일도 열 수 있게
        // 경로를 canonicalize 하지 않고, 바이너리를 실행하거나 백업을 건드리지 않는다.
        let path = bin_arg.take().unwrap_or_else(detect_default_binary);
        let mmap = MmapFile::open(&path)?;
        let ctx = BinaryContext::parse(mmap.as_slice())?;
        println!("{}", tier_query_line(&ctx));
        return Ok(());
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

    // mise 설치 디렉토리명(예: 1.5.6)은 agy 자체 업데이트 후 실제 버전과 어긋날 수 있으므로
    // 바이너리가 보고하는 버전을 함께 출력한다.
    let target_version = binary_version(&target_bin);
    println!("[*] 대상 바이너리: {} (버전 {})", target_bin.display(), target_version);

    let has_backup = target_bin != backup_bin && backup_bin.exists();
    if has_backup {
        let mut backup_version = binary_version(&backup_bin);
        // agy 자체 업데이트로 대상이 새 릴리즈 원본으로 바뀌었으면 백업도 그 원본으로 갱신한다
        if target_version != backup_version {
            let cur_mmap = MmapFile::open(&target_bin)?;
            let cur_ctx = BinaryContext::parse(cur_mmap.as_slice())?;
            if should_refresh_backup(&target_version, &backup_version, is_unpatched_cut(&cur_ctx)?) {
                copy_reflink(&target_bin, &backup_bin)?;
                println!("[+] agy 업데이트 감지: 원본 백업 갱신 ({backup_version} -> {target_version})");
                backup_version = target_version.clone();
            }
        }
        println!("[*] 패치 원본:     {} (버전 {})", backup_bin.display(), backup_version);
    }

    let src_bin = if has_backup { backup_bin.clone() } else { target_bin.clone() };

    let mmap = MmapFile::open(&src_bin)?;
    let mut ctx = BinaryContext::parse(mmap.as_slice())?;
    cli_args.apply_to(&mut ctx);

    let is_tty = unsafe { isatty(0) == 1 };
    if preset_mode
        || (!is_tty
            && patches_arg.is_none()
            && output_arg.is_none()
            && !in_place
            && cli_args.is_empty())
    {
        let mut nodrip_patches: Vec<&'static PatchSpec> =
            PATCH_REGISTRY.iter().filter(|p| p.default_on && p.id != "batch").collect();
        let mut batch_patches: Vec<&'static PatchSpec> =
            PATCH_REGISTRY.iter().filter(|p| p.default_on).collect();
        cli_args.ensure_selected(&mut nodrip_patches);
        cli_args.ensure_selected(&mut batch_patches);
        let jobs = [("agy-nodrip", nodrip_patches), ("agy-batch", batch_patches)];
        // 둘 다 먼저 검사해서 하나만 만들어진 채로 멈추는 일이 없게 한다
        let plans = jobs
            .iter()
            .map(|(name, _)| plan_output(bin_dir, &target_bin, &src_bin, name))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.message(CLI_IN_PLACE_HINT))?;
        for ((_, patches), plan) in jobs.iter().zip(&plans) {
            build_from_plan(&src_bin, &mut ctx, patches, plan)?;
        }
        return Ok(());
    }

    let (chosen_patches, out_name, do_in_place, final_args) =
        if patches_arg.is_none() && output_arg.is_none() && !in_place && cli_args.is_empty() {
            match interactive_wizard(&src_bin, &target_bin, &target_version, &ctx)? {
                Some(result) => (result.patches, result.out_name, result.in_place, result.args),
                None => {
                    println!("취소되었습니다.");
                    return Ok(());
                }
            }
        } else {
            // -p 의 '=값' 보다 --compact / --code-theme / --*-tier 가 우선한다
            let mut args = PatchArgs::default();
            let mut patches = parse_patch_list(patches_arg.as_deref().unwrap_or("all"), &mut args)?;
            cli_args.ensure_selected(&mut patches);
            args.overlay(&cli_args);
            let default_out = if patches.iter().any(|p| p.id == "batch") {
                "agy-batch"
            } else {
                "agy-patched"
            };
            let name = output_arg.unwrap_or_else(|| default_out.to_string());
            (patches, name, in_place, args)
        };
    final_args.apply_to(&mut ctx);

    if do_in_place {
        if !backup_bin.exists() {
            copy_reflink(&src_bin, &backup_bin)?;
            println!("[+] 원본 백업 저장: {}", backup_bin.display());
        }
        let backup_mmap = MmapFile::open(&backup_bin)?;
        let mut backup_ctx = BinaryContext::parse(backup_mmap.as_slice())?;
        final_args.apply_to(&mut backup_ctx);
        build_patched_binary(&backup_bin, &mut backup_ctx, &chosen_patches, &target_bin, None)?;
        println!("[+] 기본 agy 바이너리에 패치 적용 완료: {}", target_bin.display());
        return Ok(());
    }

    let plan = plan_output(bin_dir, &target_bin, &src_bin, &out_name).map_err(|e| e.message(CLI_IN_PLACE_HINT))?;
    build_from_plan(&src_bin, &mut ctx, &chosen_patches, &plan)
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
    fn backup_refreshes_only_when_agy_updated_to_another_version() {
        // agy 자체 업데이트: 버전이 바뀌었고 패치가 풀린 원본
        assert!(should_refresh_backup("1.5.13", "1.5.12", true));
        // nodrip 을 뺀 조합으로 in-place 한 패치본: nodrip 자리는 원본이지만 백업과 같은 버전이므로 지킨다
        assert!(!should_refresh_backup("1.5.13", "1.5.13", true));
        // 다른 버전이라도 nodrip 이 패치돼 있으면 원본이 아니다
        assert!(!should_refresh_backup("1.5.13", "1.5.12", false));
        // 버전을 알 수 없으면 덮어쓰지 않는다
        assert!(!should_refresh_backup(VERSION_UNKNOWN, "1.5.12", true));
        assert!(!should_refresh_backup("1.5.13", VERSION_UNKNOWN, true));
    }

    #[test]
    fn patch_list_parser_validates_ids_alongside_all() {
        let parse = |s: &str| {
            let mut args = PatchArgs::default();
            parse_patch_list(s, &mut args)
                .map(|v| (v.iter().map(|p| p.id).collect::<Vec<_>>(), args.compact, args.code_theme))
        };
        let defaults: Vec<&str> = PATCH_REGISTRY.iter().filter(|p| p.default_on).map(|p| p.id).collect();

        let err = parse("all,nodirp").expect_err("'all' 과 함께 준 오타도 거부해야 함");
        assert!(err.contains("'nodirp'"), "{err}");
        assert!(parse("nodirp").is_err());

        assert_eq!(parse("all").unwrap().0, defaults);
        assert_eq!(parse("").unwrap().0, defaults);

        let (ids, ..) = parse("all,patch-info").unwrap();
        assert_eq!(ids, [defaults.as_slice(), &["patch-info"]].concat());

        let (ids, tokens, _) = parse("all,compact=200k").unwrap();
        assert_eq!(ids, [defaults.as_slice(), &["compact"]].concat());
        assert_eq!(tokens, Some(200_000));

        let (ids, _, theme) = parse("all,code-theme=bw").unwrap();
        assert_eq!(ids, defaults);
        assert_eq!(theme.as_deref(), Some("bw"));

        assert_eq!(parse("cjk-bold, nodrip,cjk-bold").unwrap().0, ["cjk-bold", "nodrip"]);
        assert!(parse("all=1").is_err());

        let mut args = PatchArgs::default();
        let ids: Vec<_> = parse_patch_list("all,pro-tier=Gemini-4-Carbon-Medium", &mut args)
            .unwrap()
            .iter()
            .map(|p| p.id)
            .collect();
        assert_eq!(ids, [defaults.as_slice(), &["pro-tier"]].concat());
        assert_eq!(args.tiers[0].as_deref(), Some("gemini-4-carbon-medium"));
        assert!(parse("pro-tier=bad name").is_err());
    }

    #[test]
    fn patch_args_cli_values_win_and_select_their_patch() {
        let mut args = PatchArgs { compact: Some(200_000), code_theme: Some("bw".into()), tiers: [None, Some("gemini-4-neon-high".into()), None] };
        let cli = PatchArgs { compact: Some(180_000), code_theme: None, tiers: [Some("gemini-4-carbon-low".into()), None, None] };
        args.overlay(&cli);
        assert_eq!(
            args,
            PatchArgs {
                compact: Some(180_000),
                code_theme: Some("bw".into()),
                tiers: [Some("gemini-4-carbon-low".into()), Some("gemini-4-neon-high".into()), None]
            }
        );
        let mut patches = Vec::new();
        cli.ensure_selected(&mut patches);
        assert_eq!(patches.iter().map(|p| p.id).collect::<Vec<_>>(), ["compact", "pro-tier"]);
    }

    #[test]
    fn available_model_ids_keep_known_order_and_binary_presence() {
        assert_eq!(find_all(b"abcabcab", b"ab").collect::<Vec<_>>(), [0, 3, 6]);
        assert_eq!(find_all(b"aaaa", b"aa").collect::<Vec<_>>(), [0, 1, 2]);
        assert_eq!(find_all(b"abc", b"").count(), 0);

        // Go 문자열처럼 구분자 없이 붙어 있는 모델 ID 들
        let mut buf = vec![0u8; 512];
        let blob = b"..gemini-4-neon-highclaude-sonnet-5-5-lowgemini-4-carbon-highgemini-4-carbon-lowzz";
        buf[100..100 + blob.len()].copy_from_slice(blob);
        let ctx = BinaryContext {
            data: &buf,
            format: Format::Elf64,
            arch: Arch::X86_64,
            segments: Vec::new(),
            funcs: [("modelutils.modelIDForTier", (0usize, 64usize))].into_iter().collect(),
            pcln: None,
            compact_tokens: DEFAULT_COMPACT_TOKENS,
            code_theme: DEFAULT_CODE_THEME.to_string(),
            tier_models: default_tier_models(),
            text_section: None,
            selected_patches: Vec::new(),
        };
        assert_eq!(
            available_model_ids(&ctx),
            ["gemini-4-carbon-high", "gemini-4-carbon-low", "gemini-4-neon-high", "claude-sonnet-5-5-low"]
        );
        assert_eq!(find_model_id_offset(&ctx, "claude-sonnet-5-5-low"), Ok(100 + 20));
        assert!(find_model_id_offset(&ctx, "gemini-4-neon-xhigh").is_err());
    }

    fn tier_ctx<'a>(buf: &'a [u8], fn_start: usize, fn_end: usize, models: [&str; 3]) -> BinaryContext<'a> {
        BinaryContext {
            data: buf,
            format: Format::Elf64,
            arch: Arch::X86_64,
            segments: Vec::new(),
            funcs: [("modelutils.modelIDForTier", (fn_start, fn_end))].into_iter().collect(),
            pcln: None,
            compact_tokens: DEFAULT_COMPACT_TOKENS,
            code_theme: DEFAULT_CODE_THEME.to_string(),
            tier_models: models.map(str::to_string),
            text_section: None,
            selected_patches: Vec::new(),
        }
    }

    #[test]
    fn resolve_all_three_tiers_x86_in_one_function() {
        // agy 1.5.7~1.5.13 modelIDForTier: flash_lite(2)·flash(3) 는 ret 까지 37바이트, pro(4)는 24바이트 + 공용 블록
        fn branch37(tier: u8, field: u8) -> Vec<u8> {
            let mut v = vec![0x83, 0xfb, tier, 0x75, 0x2b, 0x48, 0x85, 0xc0, 0x74, 0x0a];
            v.extend([0x48, 0x8b, 0x50, field, 0x48, 0x8b, 0x70, field + 8]);
            v.extend([0xeb, 0x04, 0x31, 0xf6, 0x31, 0xd2, 0x48, 0x85, 0xf6, 0x74, 0x4a]);
            v.extend([0x48, 0x8b, 0x02, 0x48, 0x8b, 0x5a, 0x08, 0x31, 0xc9, 0x31, 0xff, 0xc9, 0xc3]);
            v.extend([0x0f, 0x1f, 0x40, 0x00]); // 정렬용 nop
            v
        }
        let mut code = branch37(2, 0x08);
        code.extend(branch37(3, 0x20));
        code.extend([0x83, 0xfb, 0x04, 0x75, 0x2f, 0x48, 0x85, 0xc0, 0x74, 0x0a, 0x48, 0x8b, 0x50, 0x38, 0x48, 0x8b, 0x70, 0x40]);
        code.extend([0xeb, 0x04, 0x31, 0xf6, 0x31, 0xd2, 0x48, 0x85, 0xf6, 0x75, 0x0a]);
        code.extend([0x31, 0xc0, 0x31, 0xdb, 0x31, 0xc9, 0x89, 0xc7, 0xc9, 0xc3]); // 공용 빈 반환 블록
        code.extend([0x48, 0x8b, 0x02, 0x48, 0x8b, 0x5a, 0x08, 0x31, 0xc9, 0x31, 0xff, 0xc9, 0xc3]);

        let mut buf = vec![0u8; 1024];
        let fn_start = 64;
        buf[fn_start..fn_start + code.len()].copy_from_slice(&code);
        let strings = b"gemini-4-carbon-highgemini-4-neon-mediumgemini-4-hydrogen-lowgemini-4-carbon-low";
        buf[600..600 + strings.len()].copy_from_slice(strings);
        let original = buf.clone();
        let fn_end = fn_start + code.len() + 16;
        let lea_target = |buf: &[u8], site: usize| {
            let t = (site as i64 + 7 + read_i32(buf, site + 3) as i64) as usize;
            String::from_utf8(buf[t..t + read_u32(buf, site + 8) as usize].to_vec()).unwrap()
        };
        let defaults = TIERS.map(|t| t.default_model);
        let sites = [(fn_start + 2 * 46 + 5, 24), (fn_start + 46 + 5, 37), (fn_start + 5, 37)]; // TIERS 순서
        for (ti, &(site, len)) in sites.iter().enumerate() {
            assert_eq!(find_tier_site_x86(&tier_ctx(&buf, fn_start, fn_end, defaults), TIERS[ti].tier), Ok((site, len, false)));
        }

        // 세 패치를 같은 원본에서 계산해 한꺼번에 쓴다 (build_patched_binary 와 같음)
        let resolvers: [Resolver; 3] = [resolve_pro_tier, resolve_flash_tier, resolve_flash_lite_tier];
        let all = |buf: &mut Vec<u8>, models: [&str; 3]| {
            let edits: Vec<ByteEdit> = resolvers.iter().flat_map(|r| r(&tier_ctx(buf, fn_start, fn_end, models)).unwrap()).collect();
            apply(buf, edits);
        };
        assert_eq!(tier_query_line(&tier_ctx(&buf, fn_start, fn_end, defaults)), "");
        all(&mut buf, defaults);
        assert_eq!(
            tier_query_line(&tier_ctx(&buf, fn_start, fn_end, defaults)),
            "pro=gemini-4-carbon-high,flash=gemini-4-neon-medium,flash_lite=gemini-4-hydrogen-low"
        );
        for (ti, &(site, len)) in sites.iter().enumerate() {
            assert_eq!(lea_target(&buf, site), TIERS[ti].default_model);
            assert!(buf[site + 18..site + len].iter().all(|&c| c == 0xcc));
            assert_eq!(detect_patched_tier(&tier_ctx(&buf, fn_start, fn_end, defaults), ti).as_deref(), Some(TIERS[ti].default_model));
            assert_eq!(find_tier_site_x86(&tier_ctx(&buf, fn_start, fn_end, defaults), TIERS[ti].tier), Ok((site, len, true)));
        }
        // 정렬용 nop 과 공용 빈 반환 블록 등 분기 밖 바이트는 그대로
        let changed: Vec<usize> = (0..buf.len()).filter(|&i| buf[i] != original[i]).collect();
        assert!(changed.iter().all(|&i| sites.iter().any(|&(s, l)| (s..s + l).contains(&i))));

        // 같은 값으로 다시 적용하면 결과가 같고, 다른 값으로 바꿀 수 있다
        let once = buf.clone();
        all(&mut buf, defaults);
        assert_eq!(buf, once);
        all(&mut buf, ["gemini-4-carbon-low", "gemini-4-carbon-high", "gemini-4-neon-medium"]);
        assert_eq!(lea_target(&buf, sites[0].0), "gemini-4-carbon-low");
        assert_eq!(lea_target(&buf, sites[2].0), "gemini-4-neon-medium");

        // 바이너리에 없는 모델은 거부
        assert!(resolve_flash_tier(&tier_ctx(&original, fn_start, fn_end, ["gemini-4-carbon-high", "gemini-4-neon-xhigh", "gemini-4-hydrogen-low"])).is_err());
    }

    #[test]
    fn model_id_parser_validates_ids() {
        assert_eq!(parse_model_id(" Gemini-4-Carbon-High "), Ok("gemini-4-carbon-high".to_string()));
        assert_eq!(parse_model_id("gemini-3.8-flash-high"), Ok("gemini-3.8-flash-high".to_string()));
        assert!(parse_model_id("").is_err());
        assert!(parse_model_id("gemini 4").is_err());
        assert!(parse_model_id("model\"").is_err());
        assert!(parse_model_id(&"a".repeat(65)).is_err());
    }

    #[test]
    fn resolve_pro_tier_x86_patches_and_repatches() {
        // agy 1.5.7~1.5.13 modelIDForTier 의 PRO(=4) 분기와 뒤따르는 공용 블록
        let mut buf = vec![0u8; 1024];
        let strings = b"xxgemini-4-carbon-highgemini-4-neon-mediumgemini-4-carbon-lowyy";
        buf[600..600 + strings.len()].copy_from_slice(strings);
        let high = 602;
        let low = 600 + strings.windows(19).position(|w| w == b"gemini-4-carbon-low").unwrap();
        let (fn_start, fn_end) = (64usize, 320usize);
        let site = fn_start + 32;
        let seq: &[u8] = &[
            0x83, 0xfb, 0x04, 0x75, 0x2f, // cmp $4,%ebx; jne
            0x48, 0x85, 0xc0, 0x74, 0x0a, // test %rax,%rax; je
            0x48, 0x8b, 0x50, 0x38, 0x48, 0x8b, 0x70, 0x40, // mov 0x38(%rax),%rdx; mov 0x40(%rax),%rsi
            0xeb, 0x04, 0x31, 0xf6, 0x31, 0xd2, // jmp; xor %esi,%esi; xor %edx,%edx
            0x48, 0x85, 0xf6, 0x75, 0x0a, // test %rsi,%rsi; jne ok
            0x31, 0xc0, 0x31, 0xdb, 0x31, 0xc9, 0x89, 0xc7, 0xc9, 0xc3, // 공용 빈 반환 블록
            0x48, 0x8b, 0x02, 0x48, 0x8b, 0x5a, 0x08, // ok: mov (%rdx),%rax; mov 8(%rdx),%rbx
        ];
        buf[site..site + seq.len()].copy_from_slice(seq);
        let shared = buf[site + 29..site + 39].to_vec();
        let ctx_with = |buf: &[u8], model: &str, arch: Arch| -> Result<Vec<ByteEdit>, String> {
            let ctx = BinaryContext {
                data: buf,
                format: Format::Elf64,
                arch,
                segments: Vec::new(),
                funcs: [("modelutils.modelIDForTier", (fn_start, fn_end))].into_iter().collect(),
                pcln: None,
                compact_tokens: DEFAULT_COMPACT_TOKENS,
                code_theme: DEFAULT_CODE_THEME.to_string(),
                tier_models: [model.to_string(), TIERS[1].default_model.to_string(), TIERS[2].default_model.to_string()],
                text_section: None,
                selected_patches: Vec::new(),
            };
            resolve_pro_tier(&ctx)
        };
        let detect = |buf: &[u8]| {
            detect_patched_tier(&BinaryContext {
                data: buf,
                format: Format::Elf64,
                arch: Arch::X86_64,
                segments: Vec::new(),
                funcs: [("modelutils.modelIDForTier", (fn_start, fn_end))].into_iter().collect(),
                pcln: None,
                compact_tokens: DEFAULT_COMPACT_TOKENS,
                code_theme: DEFAULT_CODE_THEME.to_string(),
                tier_models: default_tier_models(),
                text_section: None,
                selected_patches: Vec::new(),
            }, 0)
        };

        assert_eq!(detect(&buf), None);
        assert!(ctx_with(&buf, "gemini-9-missing", Arch::X86_64).is_err());
        assert!(ctx_with(&buf, TIERS[0].default_model, Arch::Arm64).is_err());

        let mut prev: Option<&str> = None;
        for (model, off) in [
            (TIERS[0].default_model, high),
            (TIERS[0].default_model, high),
            ("gemini-4-carbon-low", low),
            (TIERS[0].default_model, high),
        ] {
            let before = buf.clone();
            let edits = ctx_with(&buf, model, Arch::X86_64).expect("pro-tier 매칭");
            assert_eq!(edits.len(), 1);
            assert_eq!(edits[0].offset, site + 5);
            apply(&mut buf, edits);
            let b = site + 5;
            assert_eq!(&buf[b..b + 3], &[0x48, 0x8d, 0x05]);
            assert_eq!((b as i64 + 7 + read_i32(&buf, b + 3) as i64) as usize, off);
            assert_eq!(buf[b + 7], 0xbb);
            assert_eq!(read_u32(&buf, b + 8) as usize, model.len());
            assert_eq!(&buf[b + 12..b + 18], &[0x31, 0xc9, 0x31, 0xff, 0xc9, 0xc3]);
            assert!(buf[b + 18..b + 24].iter().all(|&c| c == 0xcc));
            assert_eq!(&buf[site + 29..site + 39], shared.as_slice(), "다른 티어가 쓰는 공용 블록은 그대로");
            assert_eq!(detect(&buf).as_deref(), Some(model));
            if prev == Some(model) {
                assert_eq!(buf, before, "같은 모델로 다시 패치하면 결과가 같아야 함");
            }
            prev = Some(model);
        }
    }

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
                pcln: None,
                compact_tokens: tokens,
                code_theme: DEFAULT_CODE_THEME.to_string(),
                tier_models: default_tier_models(),
                text_section: None,
                selected_patches: Vec::new(),
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
                pcln: None,
                compact_tokens: DEFAULT_COMPACT_TOKENS,
                code_theme: theme.to_string(),
                tier_models: default_tier_models(),
                text_section: None,
                selected_patches: Vec::new(),
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

    #[test]
    fn resolve_code_theme_skips_x86_alignment_nops() {
        let mut buf = vec![0x90u8; 512];
        let native_tag = b"<style name=\"native\">";
        let vs_tag = b"<style name=\"vs\">";
        buf[16..16 + native_tag.len()].copy_from_slice(native_tag);
        let native_off = 16 + 13;
        buf[64..64 + vs_tag.len()].copy_from_slice(vs_tag);
        let vs_off = 64 + 13;

        let fn_start = 160usize;
        let fn_end = 320usize;
        let site = fn_start + 12;
        buf[site..site + 2].copy_from_slice(&[0x48, 0xb8]);
        buf[site + 2..site + 10].copy_from_slice(b"terminal");
        // agy 1.5.12 에서 관측된 JCC 정렬용 1바이트 nop(0x90) 및 다중바이트 nop 삽입
        buf[site + 10] = 0x90;
        buf[site + 11..site + 14].copy_from_slice(&[0x48, 0x39, 0x02]);
        buf[site + 14..site + 18].copy_from_slice(&[0x0f, 0x1f, 0x40, 0x00]);
        buf[site + 18..site + 24].copy_from_slice(&[0x0f, 0x85, 0x50, 0x00, 0x00, 0x00]);
        let lea_off = site + 24;
        let lea_next = lea_off + 7;
        let disp_native = (native_off as i64 - lea_next as i64) as i32;
        buf[lea_off..lea_off + 3].copy_from_slice(&[0x48, 0x8d, 0x05]);
        buf[lea_off + 3..lea_next].copy_from_slice(&disp_native.to_le_bytes());
        buf[lea_next..lea_next + 8].copy_from_slice(&[0x48, 0x89, 0x84, 0x24, 0x20, 0x16, 0x00, 0x00]);
        let mov_len_off = lea_next + 8;
        buf[mov_len_off..mov_len_off + 8]
            .copy_from_slice(&[0x48, 0xc7, 0x84, 0x24, 0x28, 0x16, 0x00, 0x00]);
        buf[mov_len_off + 8..mov_len_off + 12].copy_from_slice(&6u32.to_le_bytes());

        let mut funcs = HashMap::new();
        funcs.insert("render.glamourStyleForScheme", (fn_start, fn_end));
        let ctx = BinaryContext {
            data: &buf,
            format: Format::Elf64,
            arch: Arch::X86_64,
            segments: Vec::new(),
            funcs,
            pcln: None,
            compact_tokens: DEFAULT_COMPACT_TOKENS,
            code_theme: "vs".to_string(),
            tier_models: default_tier_models(),
            text_section: None,
            selected_patches: Vec::new(),
        };
        let edits = resolve_code_theme(&ctx).expect("정렬용 NOP이 있어도 code-theme 매칭이 성공해야 함");
        assert_eq!(edits.len(), 2);
        apply(&mut buf, edits);
        assert_eq!(read_i32(&buf, lea_off + 3), (vs_off as i64 - lea_next as i64) as i32);
        assert_eq!(read_u32(&buf, mov_len_off + 8), 2);
    }

    #[test]
    fn resolve_code_theme_accepts_agy_1_5_14_glamour_style() {
        // agy 1.5.14: 함수 이름이 render.glamourStyle 로 바뀌고, "terminal" 상수와 비교 사이에
        // 비교할 문자열 포인터를 스택에서 다시 읽는다 (mov 0x19f0(%rsp),%rcx; cmp %rax,(%rcx)).
        let mut buf = vec![0x90u8; 512];
        let native_tag = b"<style name=\"native\">";
        let vs_tag = b"<style name=\"vs\">";
        buf[16..16 + native_tag.len()].copy_from_slice(native_tag);
        let native_off = 16 + 13;
        buf[64..64 + vs_tag.len()].copy_from_slice(vs_tag);
        let vs_off = 64 + 13;

        let (fn_start, fn_end) = (160usize, 320usize);
        let site = fn_start + 12;
        buf[site..site + 2].copy_from_slice(&[0x48, 0xb8]);
        buf[site + 2..site + 10].copy_from_slice(b"terminal");
        buf[site + 10..site + 18].copy_from_slice(&[0x48, 0x8b, 0x8c, 0x24, 0xf0, 0x19, 0x00, 0x00]);
        buf[site + 18..site + 21].copy_from_slice(&[0x48, 0x39, 0x01]);
        buf[site + 21..site + 27].copy_from_slice(&[0x0f, 0x85, 0xe9, 0x00, 0x00, 0x00]);
        let lea_off = site + 27;
        let lea_next = lea_off + 7;
        buf[lea_off..lea_off + 3].copy_from_slice(&[0x48, 0x8d, 0x05]);
        buf[lea_off + 3..lea_next].copy_from_slice(&((native_off as i64 - lea_next as i64) as i32).to_le_bytes());
        buf[lea_next..lea_next + 8].copy_from_slice(&[0x48, 0x89, 0x84, 0x24, 0x10, 0x15, 0x00, 0x00]);
        let mov_len_off = lea_next + 8;
        buf[mov_len_off..mov_len_off + 8].copy_from_slice(&[0x48, 0xc7, 0x84, 0x24, 0x18, 0x15, 0x00, 0x00]);
        buf[mov_len_off + 8..mov_len_off + 12].copy_from_slice(&6u32.to_le_bytes());

        fn ctx_at<'a>(buf: &'a [u8], theme: &str, range: (usize, usize)) -> BinaryContext<'a> {
            let mut funcs = HashMap::new();
            funcs.insert("render.glamourStyle", range);
            BinaryContext {
                data: buf,
                format: Format::Elf64,
                arch: Arch::X86_64,
                segments: Vec::new(),
                funcs,
                pcln: None,
                compact_tokens: DEFAULT_COMPACT_TOKENS,
                code_theme: theme.to_string(),
                tier_models: default_tier_models(),
                text_section: None,
                selected_patches: Vec::new(),
            }
        }
        let ctx_for = |buf, theme| ctx_at(buf, theme, (fn_start, fn_end));
        let owned = buf.clone();
        assert_eq!(detect_patched_code_theme(&ctx_for(&owned, "vs")), None);
        let edits = resolve_code_theme(&ctx_for(&owned, "vs")).expect("1.5.14 형태도 매칭돼야 함");
        apply(&mut buf, edits);
        assert_eq!(read_i32(&buf, lea_off + 3), (vs_off as i64 - lea_next as i64) as i32);
        assert_eq!(read_u32(&buf, mov_len_off + 8), 2);
        assert_eq!(detect_patched_code_theme(&ctx_for(&buf, "vs")).as_deref(), Some("vs"));
        // 스택 읽기가 없는 1.5.13 이하 이름만 있으면 그 이름으로 찾는다 (위 테스트들) — 둘 다 없으면 오류
        let mut ctx = ctx_for(&owned, "vs");
        ctx.funcs.clear();
        assert!(resolve_code_theme(&ctx).err().is_some_and(|e| e.contains("render.glamourStyle")));
    }

    #[test]
    fn resolve_batch_skips_x86_alignment_nops() {
        // agy 1.5.13 에서 관측된 `cmp edx, 0xb` 직전 2바이트 NOP(`66 90`) 삽입 케이스
        let mut buf = vec![0x90u8; 256];
        let fn_start = 32usize;
        let fn_end = 160usize;
        let site = fn_start + 16;
        let seq: &[u8] = &[
            0x83, 0xfe, 0x01, // cmp esi, 1
            0x76, 0x10, // jbe +0x10
            0x83, 0xfa, 0x08, // cmp edx, 8
            0x74, 0x0b, // je +0x0b
            0x66, 0x90, // xchg ax, ax (정렬용 2바이트 NOP)
            0x83, 0xfa, 0x0b, // cmp edx, 0xb
            0x0f, 0x85, 0x0b, 0x01, 0x00, 0x00, // jne +0x10b
            0x48, 0x8b, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, // mov rax, [rsp+0x90]
        ];
        buf[site..site + seq.len()].copy_from_slice(seq);

        let mut funcs = HashMap::new();
        funcs.insert("render.renderPlannerBody", (fn_start, fn_end));
        let ctx = BinaryContext {
            data: &buf,
            format: Format::Elf64,
            arch: Arch::X86_64,
            segments: Vec::new(),
            funcs,
            pcln: None,
            compact_tokens: DEFAULT_COMPACT_TOKENS,
            code_theme: "vs".to_string(),
            tier_models: default_tier_models(),
            text_section: None,
            selected_patches: Vec::new(),
        };
        let edits = resolve_batch(&ctx).expect("정렬용 NOP이 있어도 batch 매칭이 성공해야 함");
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].offset, site + 21);
        assert_eq!(edits[0].payload, vec![0x31, 0xc0, 0x31, 0xdb, 0x31, 0xc9, 0xc9, 0xc3]);
    }

    #[test]
    fn resolve_banner_x86_repatches_already_patched_binary() {
        let mut buf = vec![0u8; 4096];
        buf[1024..2048].fill(0xcc); // 1.5.9 처럼 0xcc 패딩(동굴)이 딱 한 곳뿐인 경우
        let (fn_start, fn_end) = (64usize, 256usize);
        let site = fn_start + 16;
        let stores: &[u8] = &[
            0x48, 0x89, 0x9c, 0x24, 0xb0, 0x02, 0x00, 0x00, // mov %rbx,0x2b0(%rsp)
            0x48, 0x89, 0x84, 0x24, 0x20, 0x03, 0x00, 0x00, // mov %rax,0x320(%rsp)
        ];
        buf[site..site + 9].copy_from_slice(&[0x48, 0x85, 0xd2, 0x0f, 0x84, 0x00, 0x01, 0x00, 0x00]); // test; je
        buf[site + 9..site + 25].copy_from_slice(stores);
        buf[site + 25..site + 55].fill(0xaa);

        let chan = format!("patch v{}", env!("CARGO_PKG_VERSION"));
        let mut first_round = Vec::new();
        for round in 0..2 {
            let edits = {
                let mut funcs = HashMap::new();
                funcs.insert("render.BannerWithInfo", (fn_start, fn_end));
                let ctx = BinaryContext {
                    data: &buf,
                    format: Format::Elf64,
                    arch: Arch::X86_64,
                    segments: Vec::new(),
                    funcs,
                    pcln: None,
                    compact_tokens: DEFAULT_COMPACT_TOKENS,
                    code_theme: DEFAULT_CODE_THEME.to_string(),
                    tier_models: default_tier_models(),
                    text_section: None,
                    selected_patches: Vec::new(),
                };
                resolve_banner(&ctx).unwrap_or_else(|e| panic!("{round}회차 banner 매칭 실패: {e}"))
            };
            apply(&mut buf, edits);

            // 두 저장 명령이 맨 앞에 그대로 남고, lea 가 채널 문자열을, jmp 가 원래 분기 끝을 가리킨다
            assert_eq!(&buf[site..site + 16], stores);
            let chan_off = (site as i64 + 23 + read_i32(&buf, site + 19) as i64) as usize;
            assert_eq!(&buf[chan_off..chan_off + chan.len()], chan.as_bytes());
            assert_eq!(read_u32(&buf, site + 24), chan.len() as u32);
            assert_eq!(site + 33 + read_i32(&buf, site + 29) as usize, site + 55);
            assert_eq!(chan_off, 1024, "{round}회차: 첫 패치가 쓴 동굴을 다시 써야 함");
            if round == 0 {
                first_round = buf.clone();
            }
        }
        assert_eq!(buf, first_round, "패치본을 다시 패치하면 결과가 같아야 함");
    }

    type Resolver = fn(&BinaryContext) -> Result<Vec<ByteEdit>, String>;

    /// build_patched_binary 처럼 같은 원본에서 모든 패치를 먼저 계산한 뒤 한꺼번에 쓴다.
    fn apply_x86(buf: &mut [u8], funcs: &[(&'static str, usize, usize)], resolvers: &[Resolver]) -> Result<(), String> {
        let edits = {
            let ctx = BinaryContext {
                data: buf,
                format: Format::Elf64,
                arch: Arch::X86_64,
                segments: Vec::new(),
                funcs: funcs.iter().map(|&(n, s, e)| (n, (s, e))).collect(),
                pcln: None,
                compact_tokens: DEFAULT_COMPACT_TOKENS,
                code_theme: DEFAULT_CODE_THEME.to_string(),
                tier_models: default_tier_models(),
                text_section: None,
                selected_patches: Vec::new(),
            };
            let mut all = Vec::new();
            for r in resolvers {
                all.extend(r(&ctx)?);
            }
            all
        };
        apply(buf, edits);
        Ok(())
    }

    #[test]
    fn x86_banner_and_patch_info_share_one_cave_across_repatches() {
        // 1.5.9 처럼 0xcc 동굴이 딱 한 곳뿐인 합성 바이너리
        let mut buf = vec![0u8; 8192];
        let cave = 4096usize;
        buf[cave..cave + CAVE_MIN].fill(0xcc);
        let bwi = (64usize, 256usize);
        let site = bwi.0 + 16;
        buf[site..site + 9].copy_from_slice(&[0x48, 0x85, 0xd2, 0x0f, 0x84, 0x00, 0x01, 0x00, 0x00]);
        buf[site + 9..site + 25].copy_from_slice(&[
            0x48, 0x89, 0x9c, 0x24, 0xb0, 0x02, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x20, 0x03, 0x00, 0x00,
        ]);
        buf[site + 25..site + 55].fill(0xaa);
        let bh = (256usize, 448usize);
        let (concat2, concat3) = (512usize, 576usize);
        let pat = bh.0 + 16;
        buf[pat..pat + 11].copy_from_slice(&[0x48, 0x89, 0xc7, 0x48, 0x89, 0xde, 0x31, 0xc0, 0x48, 0x8d, 0x1d]);
        buf[pat + 11..pat + 17].fill(0xaa);
        let call = pat + 17;
        buf[call] = 0xe8;
        buf[call + 1..call + 5].copy_from_slice(&((concat2 as i32) - (call as i32 + 5)).to_le_bytes());
        let funcs = [
            ("render.BannerWithInfo", bwi.0, bwi.1),
            ("render.BuildHeader", bh.0, bh.1),
            ("runtime.concatstring2", concat2, concat2 + 64),
            ("runtime.concatstring3", concat3, concat3 + 64),
        ];
        let both: &[Resolver] = &[resolve_banner, resolve_patch_info];

        let mut expected = buf.clone();
        apply_x86(&mut expected, &funcs, both).unwrap();
        assert!(expected[cave + CAVE_CHAN_OFF..].starts_with(b"patch v"));
        assert!(expected[cave + CAVE_INFO_OFF..].starts_with(b"\n\n"));

        // 같은 조합을 다시 적용 / 하나씩 어느 순서로 적용해도 결과가 같아야 한다
        let mut again = expected.clone();
        apply_x86(&mut again, &funcs, both).unwrap();
        assert_eq!(again, expected);
        for order in [[resolve_banner as Resolver, resolve_patch_info], [resolve_patch_info, resolve_banner]] {
            let mut b = buf.clone();
            for r in order {
                apply_x86(&mut b, &funcs, &[r]).unwrap();
                apply_x86(&mut b, &funcs, &[r]).unwrap();
            }
            assert_eq!(b, expected);
        }

        // 배치를 알아볼 수 없는 옛 패치본: patch-info 동굴의 banner 몫이 비어 있지 않으면 그 몫에 덮어쓰지 않고
        // 대체 배치로 다른 0xcc 구간에 쓴다 (정보 뒤에 남은 0xcc 꼬리는 고르지 않는다)
        let mut odd = buf.clone();
        apply_x86(&mut odd, &funcs, &[resolve_patch_info]).unwrap();
        odd[cave + CAVE_CHAN_OFF] = 0x00;
        let before = odd.clone();
        apply_x86(&mut odd, &funcs, &[resolve_banner]).unwrap();
        let chan_off = (site as i64 + 23 + read_i32(&odd, site + 19) as i64) as usize;
        assert_eq!(chan_off, cave + CAVE_CHAN_OFF + 1);
        assert!((0..odd.len()).filter(|&i| odd[i] != before[i]).all(|i| (site..site + 55).contains(&i) || before[i] == 0xcc));
    }

    #[test]
    fn code_cc_runs_stay_inside_code_section() {
        // 같은 실행 세그먼트의 데이터(.rodata 등)에 있는 0xcc 는 패딩이 아니므로 고르지 않는다
        let mut buf = vec![0u8; 4096];
        buf[100..140].fill(0xcc); // 코드 섹션 앞 (데이터)
        buf[1100..1140].fill(0xcc); // 코드 섹션 안
        buf[1990..2030].fill(0xcc); // 섹션 끝에 걸침 → 섹션 안쪽 10바이트만 남아 너무 짧다
        let ctx = BinaryContext {
            data: &buf,
            format: Format::Elf64,
            arch: Arch::X86_64,
            segments: Vec::new(),
            funcs: HashMap::new(),
            pcln: None,
            compact_tokens: DEFAULT_COMPACT_TOKENS,
            code_theme: DEFAULT_CODE_THEME.to_string(),
            tier_models: default_tier_models(),
            text_section: Some((1024, 2000)),
            selected_patches: Vec::new(),
        };
        assert_eq!(code_cc_runs(&ctx), Ok(vec![(1100, 1140)]));
    }

    #[test]
    fn x86_banner_and_patch_info_split_when_no_big_cave() {
        // agy 1.5.14 linux_x64 처럼 1024바이트 0xcc 동굴이 없고, 함수 사이 0xcc 구간만 있는 합성 바이너리
        let mut buf = vec![0u8; 16384];
        let bwi = (64usize, 256usize);
        let site = bwi.0 + 16;
        buf[site..site + 9].copy_from_slice(&[0x48, 0x85, 0xd2, 0x0f, 0x84, 0x00, 0x01, 0x00, 0x00]);
        buf[site + 9..site + 25].copy_from_slice(&[
            0x48, 0x89, 0x9c, 0x24, 0xb0, 0x02, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x20, 0x03, 0x00, 0x00,
        ]);
        buf[site + 25..site + 55].fill(0xaa);
        let bh = (256usize, 448usize);
        let (concat2, concat3) = (512usize, 576usize);
        let pat = bh.0 + 16;
        buf[pat..pat + 11].copy_from_slice(&[0x48, 0x89, 0xc7, 0x48, 0x89, 0xde, 0x31, 0xc0, 0x48, 0x8d, 0x1d]);
        buf[pat + 11..pat + 17].fill(0xaa);
        let call = pat + 17;
        buf[call] = 0xe8;
        buf[call + 1..call + 5].copy_from_slice(&((concat2 as i32) - (call as i32 + 5)).to_le_bytes());
        let funcs = [
            ("render.BannerWithInfo", bwi.0, bwi.1),
            ("render.BuildHeader", bh.0, bh.1),
            ("runtime.concatstring2", concat2, concat2 + 64),
            ("runtime.concatstring3", concat3, concat3 + 64),
        ];
        // 패치 정보+트램펄린이 딱 들어가는 큰 구간, 채널용 40바이트 구간, 너무 작은 구간들
        let sample_ctx = BinaryContext {
            data: &[],
            format: Format::Elf64,
            arch: Arch::X86_64,
            segments: Vec::new(),
            funcs: HashMap::new(),
            pcln: None,
            compact_tokens: DEFAULT_COMPACT_TOKENS,
            code_theme: DEFAULT_CODE_THEME.to_string(),
            tier_models: default_tier_models(),
            text_section: None,
            selected_patches: Vec::new(),
        };
        let info_len = 2 + patch_info_text(&sample_ctx).len();
        let n = 8192usize;
        let info_end = ((n + info_len + 15) & !15) + 18;
        buf[1024..1044].fill(0xcc); // 20바이트: 채널에도 작다
        buf[2048..2088].fill(0xcc); // 40바이트: 채널 자리
        buf[3072..3112].fill(0xcc); // 40바이트: 둘째 후보 (첫째만 쓴다)
        let original = buf.clone();
        let both: &[Resolver] = &[resolve_banner, resolve_patch_info];

        let with_info_run = |end: usize| {
            let mut b = original.clone();
            b[n..end].fill(0xcc);
            b
        };
        let fresh = with_info_run(info_end);
        let mut expected = fresh.clone();
        apply_x86(&mut expected, &funcs, both).unwrap();
        let chan_off = (site as i64 + 23 + read_i32(&expected, site + 19) as i64) as usize;
        assert_eq!(chan_off, 2048);
        assert!(expected[n..].starts_with(b"\n\n"));
        // 호출 자리 밖에서 바뀐 바이트는 모두 원래 0xcc 였다
        assert!((0..expected.len())
            .filter(|&i| expected[i] != fresh[i])
            .all(|i| (site..site + 55).contains(&i) || (call..call + 5).contains(&i) || fresh[i] == 0xcc));

        let mut again = expected.clone();
        apply_x86(&mut again, &funcs, both).unwrap();
        assert_eq!(again, expected);
        for order in [[resolve_banner as Resolver, resolve_patch_info], [resolve_patch_info, resolve_banner]] {
            let mut b = fresh.clone();
            for r in order {
                apply_x86(&mut b, &funcs, &[r]).unwrap();
                apply_x86(&mut b, &funcs, &[r]).unwrap();
            }
            assert_eq!(b, expected);
        }

        // 패치 정보 구간이 1바이트 모자라면 patch-info 만 실패하고 banner 는 그대로 된다
        let mut short = with_info_run(info_end - 1);
        assert!(apply_x86(&mut short.clone(), &funcs, &[resolve_patch_info]).is_err());
        apply_x86(&mut short, &funcs, &[resolve_banner]).unwrap();
        assert_eq!((site as i64 + 23 + read_i32(&short, site + 19) as i64) as usize, 2048);
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
            pcln: None,
            compact_tokens: tokens,
            code_theme: theme.to_string(),
            tier_models: default_tier_models(),
            text_section: None,
            selected_patches: Vec::new(),
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

    #[test]
    fn a64_all_three_tiers_patch_and_repatch() {
        // agy 1.5.13 macOS·Linux ARM64 modelIDForTier 와 같은 모양
        const RET_TAIL: [u32; 5] = [0xaa1f_03e2, 0xaa1f_03e3, 0xf85f_83fd, 0xf845_07fe, 0xd65f_03c0];
        let head = |field: u32| [0xb400_0060, 0xa940_1404 | (field / 8) << 15, 0x1400_0003, 0xaa1f_03e5, 0xaa1f_03e4];
        let mut code: Vec<u32> = vec![0xf940_0b90, 0xeb30_63ff, 0x5400_0ae9, 0xf81b_0ffe, 0xf81f_83fd, 0xd100_23fd];
        for (tier, field) in [(2u32, 8u32), (3, 0x20)] {
            code.extend([0x7100_003f | tier << 10, 0x5400_01a1]); // cmp w1,#tier; b.ne 다음 티어
            code.extend(head(field));
            code.extend([0xb400_0005 | 0x3f << 5, 0xa940_0480]); // cbz x5,empty; ldp x0,x1,[x4]
            code.extend(RET_TAIL);
        }
        code.extend([0x7100_103f, 0x5400_0281]);
        code.extend(head(0x38));
        code.push(0xb500_0005 | 8 << 5); // cbnz x5, ok(+0x20)
        code.extend([0xaa1f_03e0, 0xaa1f_03e1, 0xaa1f_03e2, 0xaa1f_03e3, 0xf85f_83fd, 0xf845_07fe, 0xd65f_03c0]); // 공용 빈 반환
        code.push(0xa940_0480); // ok: ldp x0,x1,[x4]
        code.extend(RET_TAIL);

        let mut buf = vec![0u8; 0x3000];
        let fn_start = 0x100;
        put_words(&mut buf, fn_start, &code);
        let strings = b"gemini-4-carbon-highgemini-4-neon-mediumgemini-4-hydrogen-lowgemini-4-carbon-low";
        buf[0x2345..0x2345 + strings.len()].copy_from_slice(strings);
        let original = buf.clone();
        let funcs = [("modelutils.modelIDForTier", fn_start, fn_start + code.len() * 4 + 16)];
        let ctx_with = |buf: &[u8], models: [&str; 3]| -> Vec<ByteEdit> {
            let mut ctx = a64_ctx(buf, &funcs, DEFAULT_COMPACT_TOKENS, DEFAULT_CODE_THEME);
            ctx.tier_models = models.map(str::to_string);
            [resolve_pro_tier, resolve_flash_tier, resolve_flash_lite_tier].iter().flat_map(|r| r(&ctx).unwrap()).collect()
        };
        let defaults = TIERS.map(|t| t.default_model);
        // TIERS 순서(pro, flash, flash_lite)의 본문 시작과 반환 꼬리
        let bodies = [fn_start + 4 * (6 + 2 * 14 + 2), fn_start + 4 * (6 + 14 + 2), fn_start + 4 * (6 + 2)]; // 티어 2·3 덩어리는 14워드
        let tails = [bodies[0] + 4 * (6 + 7 + 1), bodies[1] + 28, bodies[2] + 28];
        let a64 = a64_ctx(&buf, &funcs, DEFAULT_COMPACT_TOKENS, DEFAULT_CODE_THEME);
        for ti in 0..3 {
            assert_eq!(find_tier_site_a64(&a64, TIERS[ti].tier), Ok((bodies[ti], tails[ti], false)));
        }
        assert_eq!(tier_query_line(&a64), "");

        let edits = ctx_with(&buf, defaults);
        apply(&mut buf, edits);
        let a64 = a64_ctx(&buf, &funcs, DEFAULT_COMPACT_TOKENS, DEFAULT_CODE_THEME);
        for ti in 0..3 {
            let b = bodies[ti];
            let target = a64::adrp_target(word(&buf, b), b) + a64::add_imm12(word(&buf, b + 4));
            assert_eq!(&buf[target..target + defaults[ti].len()], defaults[ti].as_bytes());
            assert_eq!(word(&buf, b + 8), a64::movz(1, defaults[ti].len() as u32));
            assert_eq!(a64::branch26_target(word(&buf, b + 12), b + 12), tails[ti]);
            assert_eq!(find_tier_site_a64(&a64, TIERS[ti].tier), Ok((b, tails[ti], true)));
            assert_eq!(detect_patched_tier(&a64, ti).as_deref(), Some(defaults[ti]));
        }
        assert_eq!(
            tier_query_line(&a64),
            "pro=gemini-4-carbon-high,flash=gemini-4-neon-medium,flash_lite=gemini-4-hydrogen-low"
        );
        // 각 본문의 앞 16바이트만 바뀐다 (공용 빈 반환 블록·반환 꼬리는 그대로)
        assert!((0..buf.len()).filter(|&i| buf[i] != original[i]).all(|i| bodies.iter().any(|&b| (b..b + 16).contains(&i))));

        // 같은 값으로 다시 적용하면 같고, 다른 값으로 바꿀 수 있다
        let once = buf.clone();
        let edits = ctx_with(&buf, defaults);
        apply(&mut buf, edits);
        assert_eq!(buf, once);
        let edits = ctx_with(&buf, ["gemini-4-carbon-low", "gemini-4-carbon-high", "gemini-4-neon-medium"]);
        apply(&mut buf, edits);
        let a64 = a64_ctx(&buf, &funcs, DEFAULT_COMPACT_TOKENS, DEFAULT_CODE_THEME);
        assert_eq!(detect_patched_tier(&a64, 0).as_deref(), Some("gemini-4-carbon-low"));
        assert_eq!(detect_patched_tier(&a64, 2).as_deref(), Some("gemini-4-neon-medium"));
    }

    #[test]
    fn pclntab_symbol_lookup_and_filetab_fallback_work() {
        // Go 1.20+ .gopclntab 합성: 심볼 이름이 미래 버전에서 바뀌어도 filetab("cli/render/markdown.go")과
        // 문자열 VA 역추적("native" / "<style name=\"...\"")만으로 code-theme 자리를 정확히 찾아낸다.
        assert_eq!(
            short_go_symbol("github.com/a/b.(*Foo[github.com/c/d.Bar]).Baz"),
            "b.(*Foo[github.com/c/d.Bar]).Baz"
        );
        assert_eq!(short_go_symbol("strings.Join"), "strings.Join");

        let mut buf = vec![0u8; 4096];
        let native_tag = b"<style name=\"native\">";
        let vs_tag = b"<style name=\"vs\">";
        buf[32..32 + native_tag.len()].copy_from_slice(native_tag);
        let native_off = 32 + 13;
        buf[96..96 + vs_tag.len()].copy_from_slice(vs_tag);
        let vs_off = 96 + 13;

        let go_text_off = 256usize;
        // fn0 (@256..320): strings.Join
        // fn1 (@320..512): 미래 버전에서 이름이 바뀐 함수 "google3/cli/render/render.futureThemeSelector"
        //   앞에 "terminal" 비교 없이 곧장 lea "native"(%rip), %rcx; mov %rcx, 0x20(%rsp); movq $6, 0x28(%rsp)
        let f1_start = 320usize;
        let lea_off = f1_start + 16;
        let lea_next = lea_off + 7;
        let disp_native = (native_off as i64 - lea_next as i64) as i32;
        buf[lea_off..lea_off + 3].copy_from_slice(&[0x48, 0x8d, 0x0d]); // lea disp(%rip), %rcx
        buf[lea_off + 3..lea_next].copy_from_slice(&disp_native.to_le_bytes());
        buf[lea_next..lea_next + 5].copy_from_slice(&[0x48, 0x89, 0x4c, 0x24, 0x20]); // disp8 store ptr
        let mov_len_off = lea_next + 5;
        buf[mov_len_off..mov_len_off + 5].copy_from_slice(&[0x48, 0xc7, 0x44, 0x24, 0x28]); // disp8 store len
        buf[mov_len_off + 5..mov_len_off + 9].copy_from_slice(&6u32.to_le_bytes());

        // .gopclntab 조립 (@1024)
        let pcln_base = 1024usize;
        let funcname_base = pcln_base + 128;
        let n0 = b"strings.Join\0";
        let n1 = b"google3/cli/render/render.futureThemeSelector\0";
        buf[funcname_base..funcname_base + n0.len()].copy_from_slice(n0);
        buf[funcname_base + n0.len()..funcname_base + n0.len() + n1.len()].copy_from_slice(n1);

        let filetab_base = pcln_base + 256;
        let f0 = b"strings/strings.go\0";
        let f1 = b"google3/third_party/cli/render/markdown.go\0";
        buf[filetab_base..filetab_base + f0.len()].copy_from_slice(f0);
        buf[filetab_base + f0.len()..filetab_base + f0.len() + f1.len()].copy_from_slice(f1);

        let cu_base = pcln_base + 384;
        buf[cu_base..cu_base + 4].copy_from_slice(&0u32.to_le_bytes());
        buf[cu_base + 4..cu_base + 8].copy_from_slice(&(f0.len() as u32).to_le_bytes());

        // pctab: offset 0 은 미사용(0), offset 1 은 sdelta=+1 -> zigzag uvdelta=2 (fno = -1 + 1 = 0)
        let pctab_base = pcln_base + 448;
        buf[pctab_base + 1] = 0x02;

        // ftab: nfunc=2 + sentinel 1개 = 24바이트, 뒤에 _func 메타데이터 2개(각 40바이트)
        let ftab_base = pcln_base + 512;
        let meta0_rel = 24u32;
        let meta1_rel = 64u32;
        buf[ftab_base..ftab_base + 4].copy_from_slice(&0u32.to_le_bytes());
        buf[ftab_base + 4..ftab_base + 8].copy_from_slice(&meta0_rel.to_le_bytes());
        buf[ftab_base + 8..ftab_base + 12].copy_from_slice(&((f1_start - go_text_off) as u32).to_le_bytes());
        buf[ftab_base + 12..ftab_base + 16].copy_from_slice(&meta1_rel.to_le_bytes());
        buf[ftab_base + 16..ftab_base + 20].copy_from_slice(&(512 - go_text_off as u32).to_le_bytes());

        // _func 0 (strings.Join: nameOff=0, pcfile=1, cuOffset=0)
        let m0 = ftab_base + meta0_rel as usize;
        buf[m0 + 4..m0 + 8].copy_from_slice(&0i32.to_le_bytes());
        buf[m0 + 20..m0 + 24].copy_from_slice(&1u32.to_le_bytes());
        buf[m0 + 32..m0 + 36].copy_from_slice(&0u32.to_le_bytes());

        // _func 1 (futureThemeSelector: nameOff=n0.len(), pcfile=1, cuOffset=1)
        let m1 = ftab_base + meta1_rel as usize;
        buf[m1 + 4..m1 + 8].copy_from_slice(&(n0.len() as i32).to_le_bytes());
        buf[m1 + 20..m1 + 24].copy_from_slice(&1u32.to_le_bytes());
        buf[m1 + 32..m1 + 36].copy_from_slice(&1u32.to_le_bytes());

        let pcln = PclnTab {
            nfunc: 2,
            go_text_off,
            funcname_base,
            cu_base,
            filetab_base,
            pctab_base,
            ftab_base,
        };
        assert_eq!(pcln.func_at_entry(&buf, 256), Some("strings.Join"));
        assert_eq!(pcln.func_at_entry(&buf, 260), None);
        assert_eq!(pcln.func_at_entry(&buf, f1_start), Some("google3/cli/render/render.futureThemeSelector"));
        assert_eq!(pcln.func_first_file(&buf, 1), Some("google3/third_party/cli/render/markdown.go"));

        fn make_ctx(b: &[u8], pcln: PclnTab) -> BinaryContext<'_> {
            BinaryContext {
                data: b,
                format: Format::Elf64,
                arch: Arch::X86_64,
                segments: Vec::new(),
                funcs: HashMap::new(), // 심볼 이름 매칭 실패 상황 시뮬레이션
                pcln: Some(pcln),
                compact_tokens: DEFAULT_COMPACT_TOKENS,
                code_theme: "vs".to_string(),
                tier_models: default_tier_models(),
                text_section: None,
                selected_patches: Vec::new(),
            }
        }

        assert_eq!(detect_patched_code_theme(&make_ctx(&buf, pcln)), None);
        let edits =
            resolve_code_theme(&make_ctx(&buf, pcln)).expect("filetab 폴백 + 문자열 VA 역추적으로 매칭 성공해야 함");
        apply(&mut buf, edits);
        assert_eq!(read_i32(&buf, lea_off + 3), (vs_off as i64 - lea_next as i64) as i32);
        assert_eq!(read_u32(&buf, mov_len_off + 5), 2);
        assert_eq!(detect_patched_code_theme(&make_ctx(&buf, pcln)).as_deref(), Some("vs"));
    }

    #[test]
    fn resolvers_tolerate_stack_offset_register_and_callgraph_variations() {
        // 1) tilde-strike: disp32 스택 로드 + 정렬 NOP + 다른 인자 순서여도 CALL parser.ScanDelimiter 역참조로 매칭
        let mut buf = vec![0x90u8; 1024];
        let scan_delim = 640usize;
        let parse_fn = (64usize, 256usize);
        let mov_esi = parse_fn.0 + 20;
        buf[mov_esi..mov_esi + 5].copy_from_slice(&[0xbe, 0x01, 0x00, 0x00, 0x00]); // mov $1, %esi
        buf[mov_esi + 5..mov_esi + 13].copy_from_slice(&[0x8b, 0xbc, 0x24, 0x40, 0x01, 0x00, 0x00, 0x90]); // disp32 + nop
        let call_sd = mov_esi + 13;
        buf[call_sd] = 0xe8;
        buf[call_sd + 1..call_sd + 5].copy_from_slice(&((scan_delim as i32) - (call_sd as i32 + 5)).to_le_bytes());

        let ctx = BinaryContext {
            data: &buf,
            format: Format::Elf64,
            arch: Arch::X86_64,
            segments: Vec::new(),
            funcs: [
                ("extension.(*strikethroughParser).Parse", parse_fn),
                ("parser.ScanDelimiter", (scan_delim, scan_delim + 64)),
            ]
            .into_iter()
            .collect(),
            pcln: None,
            compact_tokens: DEFAULT_COMPACT_TOKENS,
            code_theme: DEFAULT_CODE_THEME.to_string(),
            tier_models: default_tier_models(),
            text_section: None,
            selected_patches: Vec::new(),
        };
        let edits = resolve_tilde_strike(&ctx).expect("CALL ScanDelimiter 역참조로 tilde-strike 매칭");
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].offset, mov_esi + 1);
        assert_eq!(edits[0].payload, vec![0x02]);

        // 2) banner: disp8(5바이트*2=10바이트) 스택 저장 + 49바이트 동적 "stab" 블록 패치 및 재패치
        let mut bbuf = vec![0u8; 4096];
        bbuf[2048..3072].fill(0xcc);
        let bwi = (64usize, 256usize);
        let bsite = bwi.0 + 16;
        bbuf[bsite..bsite + 9].copy_from_slice(&[0x48, 0x85, 0xd2, 0x0f, 0x84, 0x80, 0x00, 0x00, 0x00]);
        let disp8_stores = [0x48, 0x89, 0x5c, 0x24, 0x30, 0x48, 0x89, 0x44, 0x24, 0x38]; // 10바이트
        bbuf[bsite + 9..bsite + 19].copy_from_slice(&disp8_stores);
        bbuf[bsite + 19..bsite + 24].copy_from_slice(&[0x48, 0x8b, 0x4c, 0x24, 0x40]); // mov 0x40(%rsp),%rcx
        bbuf[bsite + 24..bsite + 30].copy_from_slice(&[0x48, 0x83, 0xfa, 0x06, 0x75, 0x13]); // cmp $6,%rdx; jne +0x13 (-> bsite+49)
        bbuf[bsite + 30..bsite + 36].copy_from_slice(&[0x81, 0x39, 0x73, 0x74, 0x61, 0x62]); // cmpl "stab",(%rcx)
        bbuf[bsite + 36..bsite + 49].fill(0x90);

        let mut prev_b = Vec::new();
        for round in 0..2 {
            let bctx = BinaryContext {
                data: &bbuf,
                format: Format::Elf64,
                arch: Arch::X86_64,
                segments: Vec::new(),
                funcs: [("render.BannerWithInfo", bwi)].into_iter().collect(),
                pcln: None,
                compact_tokens: DEFAULT_COMPACT_TOKENS,
                code_theme: DEFAULT_CODE_THEME.to_string(),
                tier_models: default_tier_models(),
                text_section: None,
                selected_patches: Vec::new(),
            };
            let bedits = resolve_banner(&bctx).unwrap_or_else(|e| panic!("{round}회차 동적 banner 실패: {e}"));
            assert_eq!(bedits[1].payload.len(), 49);
            apply(&mut bbuf, bedits);
            assert_eq!(&bbuf[bsite..bsite + 10], &disp8_stores);
            if round == 0 {
                prev_b = bbuf.clone();
            }
        }
        assert_eq!(bbuf, prev_b);

        // 3) patch-info: 인자 순서 변경 + NOP 삽입에도 CALL strings.Join -> CALL runtime.concatstring2 콜그래프로 매칭
        let mut rbuf = vec![0u8; 4096];
        rbuf[2048..3072].fill(0xcc);
        let bh = (64usize, 256usize);
        let (join_fn, c2_fn, c3_fn) = (512usize, 576usize, 640usize);
        let call_join = bh.0 + 24;
        rbuf[call_join] = 0xe8;
        rbuf[call_join + 1..call_join + 5].copy_from_slice(&((join_fn as i32) - (call_join as i32 + 5)).to_le_bytes());
        // 기존 하드코딩 바이트열(48 89 c7 48 89 de ...) 없이 전혀 다른 명령들과 NOP만 배치
        rbuf[call_join + 5..call_join + 21].fill(0x90);
        let call_c2 = call_join + 21;
        rbuf[call_c2] = 0xe8;
        rbuf[call_c2 + 1..call_c2 + 5].copy_from_slice(&((c2_fn as i32) - (call_c2 as i32 + 5)).to_le_bytes());
        let rfuncs = [
            ("render.BuildHeader", bh.0, bh.1),
            ("strings.Join", join_fn, join_fn + 32),
            ("runtime.concatstring2", c2_fn, c2_fn + 32),
            ("runtime.concatstring3", c3_fn, c3_fn + 32),
        ];
        apply_x86(&mut rbuf, &rfuncs, &[resolve_patch_info]).expect("콜그래프 기반 patch-info 1회차");
        let r_once = rbuf.clone();
        apply_x86(&mut rbuf, &rfuncs, &[resolve_patch_info]).expect("콜그래프 기반 patch-info 2회차 재패치");
        assert_eq!(rbuf, r_once);

        // 4) cjk-bold: disp32 스택 오프셋(8바이트 movzbl)으로 인해 모든 분기 변위가 달라진 ScanDelimiter 매칭
        let mut cbuf = vec![0x90u8; 512];
        let sd = (32usize, 320usize);
        let p = sd.0 + 16;
        // left: test %r8b,%r8b (3B); je else1(+23 -> p+28); movzbl 0x126(%rsp),%edx (8B); test %dl,%dl (2B);
        //       jne mov1(+19 -> p+36); movzbl 0x12a(%rsp),%ebx (8B); jmp after_mov1(+13 -> p+41)
        // else1(p+28): movzbl 0x126(%rsp),%edx (8B); mov1(p+36): mov $1,%ebx (5B)
        // after_mov1(p+41): test %dl,%dl (2B); je right_else(+14 -> p+57); mov %eax,%ecx (2B);
        //                   movzbl 0x12a(%rsp),%edx (8B); xor %eax,%eax (2B); jmp end(+21 -> p+78)
        // right_else(p+57): movzbl 0x12a(%rsp),%edx (8B); test2(p+65): test %dl,%dl (2B);
        //                   je else2(+8 -> p+75); test %cl,%cl (2B); jne else2(+4 -> p+75); mov %eax,%ecx (2B); jmp end(+7)
        // else2(p+75): mov %eax,%ecx (2B); mov $1,%eax (5B)
        let mut seq = Vec::new();
        seq.extend_from_slice(&[0x45, 0x84, 0xc0]); // 0..3: test %r8b,%r8b
        seq.extend_from_slice(&[0x74, 23]); // 3..5: je +23 (-> 28)
        seq.extend_from_slice(&[0x0f, 0xb6, 0x94, 0x24, 0x26, 0x01, 0x00, 0x00]); // 5..13
        seq.extend_from_slice(&[0x84, 0xd2, 0x75, 19]); // 13..17 (-> 36)
        seq.extend_from_slice(&[0x0f, 0xb6, 0x9c, 0x24, 0x2a, 0x01, 0x00, 0x00]); // 17..25
        seq.extend_from_slice(&[0xeb, 14]); // 25..27 (-> 41)
        seq.push(0x90); // 27..28 정렬 NOP
        seq.extend_from_slice(&[0x0f, 0xb6, 0x94, 0x24, 0x26, 0x01, 0x00, 0x00]); // 28..36 (else1)
        seq.extend_from_slice(&[0xbb, 0x01, 0x00, 0x00, 0x00]); // 36..41 (mov1)
        seq.extend_from_slice(&[0x84, 0xd2, 0x74, 14]); // 41..45 (-> 59)
        seq.extend_from_slice(&[0x89, 0xc1]); // 45..47
        seq.extend_from_slice(&[0x0f, 0xb6, 0x94, 0x24, 0x2a, 0x01, 0x00, 0x00]); // 47..55
        seq.extend_from_slice(&[0x31, 0xc0, 0xeb, 24]); // 55..59
        seq.extend_from_slice(&[0x0f, 0xb6, 0x94, 0x24, 0x2a, 0x01, 0x00, 0x00]); // 59..67 (right_else)
        seq.extend_from_slice(&[0x84, 0xd2, 0x74, 8]); // 67..71 (test2 + br2 @69 -> 79)
        seq.extend_from_slice(&[0x84, 0xc9, 0x75, 4, 0x89, 0xc1, 0xeb, 7]); // 71..79
        seq.extend_from_slice(&[0x89, 0xc1, 0xb8, 0x01, 0x00, 0x00, 0x00]); // 79..86 (else2)
        cbuf[p..p + seq.len()].copy_from_slice(&seq);

        apply_x86(&mut cbuf, &[("parser.ScanDelimiter", sd.0, sd.1)], &[resolve_cjk_bold])
            .expect("disp32 + REX 변형 ScanDelimiter 매칭");
        assert_eq!(cbuf[p + 3], 0xeb);
        assert_eq!(cbuf[p + 69], 0xeb);
        let c_once = cbuf.clone();
        apply_x86(&mut cbuf, &[("parser.ScanDelimiter", sd.0, sd.1)], &[resolve_cjk_bold])
            .expect("disp32 변형 ScanDelimiter 재패치");
        assert_eq!(cbuf, c_once);
    }

    #[test]
    fn real_agy_corpus_all_versions_resolve_and_repatch_cleanly() {
        // 로컬에 실제 agy 원본 바이너리들이 있을 때만 실행 (CI 환경에서는 조용히 건너뜀, 디스크 쓰기 0)
        let Some(home) = env::var_os("HOME").map(PathBuf::from) else {
            return;
        };
        let base = home.join(".local/share/mise/installs/agy");
        for ver in ["1.5.7", "1.5.9", "1.5.10", "1.5.12", "1.5.13", "1.5.14"] {
            let orig_path = base.join(ver).join("antigravity.orig");
            if !orig_path.exists() {
                continue;
            }
            let mmap = MmapFile::open(&orig_path).unwrap_or_else(|e| panic!("{ver} 열기 실패: {e}"));
            let mut buf = mmap.as_slice().to_vec();
            drop(mmap);

            // 1) 원본 해석 + 심볼 이름 제거 시 filetab 폴백이 정확히 같은 오프셋을 찾는지 교차 검증
            let first_offsets: (Vec<(&str, Vec<usize>)>, [String; 3]) = {
                let mut run_ctx = BinaryContext::parse(&buf).unwrap_or_else(|e| panic!("{ver} 파싱 실패: {e}"));
                assert!(run_ctx.pcln.is_some());
                assert_eq!(is_unpatched_cut(&run_ctx), Ok(true));

                let fallback_model = KNOWN_MODEL_IDS
                    .iter()
                    .copied()
                    .find(|m| find_model_id_offset(&run_ctx, m).is_ok());
                if let Some(first_model) = fallback_model {
                    for i in 0..run_ctx.tier_models.len() {
                        if find_model_id_offset(&run_ctx, &run_ctx.tier_models[i]).is_err() {
                            run_ctx.tier_models[i] = first_model.to_string();
                        }
                    }
                }
                let final_tiers = run_ctx.tier_models.clone();

                let mut fb_run = BinaryContext::parse(&buf).unwrap();
                fb_run.tier_models = final_tiers.clone();
                for renamed in [
                    "store.cutAtRuneBoundary",
                    "render.renderPlannerBody",
                    "parser.ScanDelimiter",
                    "extension.(*strikethroughParser).Parse",
                    "render.glamourStyleForScheme",
                    "render.glamourStyle",
                    "config.applyFeatureProviderCheckpointOverrideConfig",
                    "utils.GetCheckpointConfig",
                    "modelutils.modelIDForTier",
                    "render.BannerWithInfo",
                    "render.BuildHeader",
                ] {
                    fb_run.funcs.remove(renamed);
                }

                let mut all_edits = Vec::new();
                let mut recorded = Vec::new();
                for spec in PATCH_REGISTRY {
                    if fallback_model.is_none() {
                        if let Some(ti) = tier_index(spec.id) {
                            // 모델 문자열 자체가 아직 없던 초기 버전은 티어 분기 사이트 매칭만 검증
                            assert!(tier_site_found(&run_ctx, TIERS[ti].tier), "{ver} {}: 티어 분기 실패", spec.id);
                            assert_eq!(
                                find_tier_site_x86(&run_ctx, TIERS[ti].tier),
                                find_tier_site_x86(&fb_run, TIERS[ti].tier),
                                "{ver} {}: filetab 폴백 불일치",
                                spec.id
                            );
                            continue;
                        }
                    }
                    let edits = (spec.resolver)(&run_ctx)
                        .unwrap_or_else(|e| panic!("{ver} [{}] 1회차 매칭 실패: {e}", spec.id));
                    let fb_edits = (spec.resolver)(&fb_run)
                        .unwrap_or_else(|e| panic!("{ver} [{}] filetab 폴백 실패: {e}", spec.id));
                    let a: Vec<usize> = edits.iter().map(|e| e.offset).collect();
                    let b: Vec<usize> = fb_edits.iter().map(|e| e.offset).collect();
                    assert_eq!(a, b, "{ver} [{}] 심볼 경로와 filetab 폴백 오프셋이 다름", spec.id);
                    recorded.push((spec.id, a));
                    all_edits.extend(edits);
                }
                apply(&mut buf, all_edits);
                (recorded, final_tiers)
            };

            // 2) 패치 적용된 인메모리 바이너리를 다시 열어 재패치 멱등성 검증
            let once = buf.clone();
            {
                let mut repatch_ctx = BinaryContext::parse(&buf).unwrap_or_else(|e| panic!("{ver} 재파싱 실패: {e}"));
                assert_eq!(is_unpatched_cut(&repatch_ctx), Ok(false));
                assert_eq!(detect_patched_code_theme(&repatch_ctx).as_deref(), Some(DEFAULT_CODE_THEME));
                assert_eq!(detect_patched_compact_tokens(&repatch_ctx), Some(DEFAULT_COMPACT_TOKENS));
                repatch_ctx.tier_models = first_offsets.1;
                let mut all_re_edits = Vec::new();
                for (id, orig_offs) in &first_offsets.0 {
                    let spec = PATCH_REGISTRY.iter().find(|p| p.id == *id).unwrap();
                    let edits = (spec.resolver)(&repatch_ctx)
                        .unwrap_or_else(|e| panic!("{ver} [{id}] 2회차 재패치 실패: {e}"));
                    let re_offs: Vec<usize> = edits.iter().map(|e| e.offset).collect();
                    assert_eq!(&re_offs, orig_offs, "{ver} [{id}] 재패치 오프셋 불일치");
                    all_re_edits.extend(edits);
                }
                apply(&mut buf, all_re_edits);
            }
            assert_eq!(buf, once, "{ver} 전체 패치 재적용 결과가 1회차와 바이트 단위로 같아야 함");
        }
    }

    #[test]
    fn patch_info_text_reflects_selected_patches_and_settings() {
        let ver = format!("v{}", env!("CARGO_PKG_VERSION"));
        let mut ctx = BinaryContext {
            data: &[],
            format: Format::Elf64,
            arch: Arch::X86_64,
            segments: Vec::new(),
            funcs: HashMap::new(),
            pcln: None,
            compact_tokens: 180_000,
            code_theme: "solarized-light".to_string(),
            tier_models: [
                "gemini-4-carbon-high".to_string(),
                "gemini-4-neon-medium".to_string(),
                "gemini-4-hydrogen-low".to_string(),
            ],
            text_section: None,
            selected_patches: vec!["nodrip", "batch", "code-theme", "compact", "pro-tier", "banner", "patch-info"],
        };
        let txt = patch_info_text(&ctx);
        assert!(!txt.contains(&ver), "banner 활성 시 중복 버전 줄을 생략해야 함");
        assert!(!txt.contains("banner"), "patches 목록에서 banner 를 제외해야 함");
        assert!(txt.contains("│ patches   \x1b[0m  nodrip\x1b[90m · \x1b[0mbatch"));
        assert!(txt.contains("│ theme     \x1b[0m  \x1b[36msolarized-light\x1b[0m  \x1b[90m·  compact\x1b[0m \x1b[36m180k\x1b[0m"));
        assert!(!txt.contains("tokens"));
        assert!(txt.contains("│ pro       \x1b[0m  \x1b[36mgemini-4-carbon-high\x1b[0m"));
        assert!(!txt.contains("│ flash"));
        assert!(!txt.contains("patch-info"));

        // banner 미선택 + compact 단독 선택 시 버전 줄과 compact 단독 줄 표시
        ctx.selected_patches = vec!["nodrip", "compact", "patch-info"];
        let no_banner = patch_info_text(&ctx);
        assert!(no_banner.contains(&format!("│ patch     \x1b[0m  \x1b[36m{ver}\x1b[0m")));
        assert!(no_banner.contains("│ compact   \x1b[0m  \x1b[36m180k\x1b[0m"));
        assert!(!no_banner.contains("│ theme"));

        // patch-info 단독 선택 시 버전 줄 + patches none 표시
        ctx.selected_patches = vec!["patch-info"];
        let only_info = patch_info_text(&ctx);
        assert!(only_info.contains(&ver));
        assert!(only_info.contains("│ patches   \x1b[0m  \x1b[90mnone\x1b[0m"));

        // 사전 가용성 검사(빈 selected_patches): 전체 기능 기준, 대체 배치 최소(256B) 이상 및 동굴 한도 이내
        ctx.selected_patches.clear();
        let full = patch_info_text(&ctx);
        assert!(full.contains("│ pro       \x1b[0m"));
        assert!(full.contains("│ flash     \x1b[0m"));
        assert!(full.contains("│ flash_lite\x1b[0m"));
        assert!(full.contains("│ theme     \x1b[0m"));
        assert!(full.contains("compact\x1b[0m \x1b[36m180k\x1b[0m"));
        assert!(2 + full.len() + 18 >= 256);
        assert!(2 + full.len() + 32 <= CAVE_MIN - CAVE_INFO_OFF);
    }
}
