//! Módulo de compatibilidade de runtime para sistemas operacionais legados (Windows 7 / Windows 8 / Server 2008 R2).
//!
//! O compilador Rust 1.76+ e certas bibliotecas modernas vinculam diretamente as seguintes APIs:
//! - `GetSystemTimePreciseAsFileTime` (introduzida no Windows 8) em `kernel32.dll`
//! - `ProcessPrng` (introduzida no Windows 10 / 8) em `bcryptprimitives.dll`
//! - `WaitOnAddress`, `WakeByAddressAll`, `WakeByAddressSingle` (introduzidas no Windows 8) em `api-ms-win-core-synch-l1-2-0.dll`
//!
//! Este módulo intercepta e provê essas funções no próprio executável:
//! Se executado no Windows 8/10/11, carrega dinamicamente a versão nativa de alta precisão.
//! Se executado no Windows 7, faz fallback transparente para as APIs disponíveis (`GetSystemTimeAsFileTime`,
//! `RtlGenRandom` / `SystemFunction036` e `ConditionVariable`/`SRWLock`).
//! Isso elimina os erros `STATUS_ENTRYPOINT_NOT_FOUND` no carregador do Windows 7.

use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

extern "system" {
    fn GetModuleHandleA(lpModuleName: *const u8) -> *mut std::ffi::c_void;
    fn LoadLibraryA(lpLibFileName: *const u8) -> *mut std::ffi::c_void;
    fn GetProcAddress(hModule: *mut std::ffi::c_void, lpProcName: *const u8) -> *mut std::ffi::c_void;
    fn GetSystemTimeAsFileTime(lpSystemTimeAsFileTime: *mut std::ffi::c_void);
    fn AcquireSRWLockExclusive(SRWLock: *mut std::ffi::c_void);
    fn ReleaseSRWLockExclusive(SRWLock: *mut std::ffi::c_void);
    fn SleepConditionVariableSRW(
        ConditionVariable: *mut std::ffi::c_void,
        SRWLock: *mut std::ffi::c_void,
        dwMilliseconds: u32,
        Flags: u32,
    ) -> i32;
    fn WakeConditionVariable(ConditionVariable: *mut std::ffi::c_void);
    fn WakeAllConditionVariable(ConditionVariable: *mut std::ffi::c_void);
}

// =========================================================================
// 1. GetSystemTimePreciseAsFileTime (Windows 8+ -> Windows 7 fallback)
// =========================================================================

#[no_mangle]
pub unsafe extern "system" fn GetSystemTimePreciseAsFileTime(lp_file_time: *mut std::ffi::c_void) {
    static REAL_FN: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
    static INITIALIZED: AtomicBool = AtomicBool::new(false);

    if !INITIALIZED.load(Ordering::Acquire) {
        let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        if !kernel32.is_null() {
            let proc = GetProcAddress(kernel32, b"GetSystemTimePreciseAsFileTime\0".as_ptr());
            if !proc.is_null() {
                REAL_FN.store(proc, Ordering::Release);
            }
        }
        INITIALIZED.store(true, Ordering::Release);
    }

    let real = REAL_FN.load(Ordering::Acquire);
    if !real.is_null() {
        let f: unsafe extern "system" fn(*mut std::ffi::c_void) = std::mem::transmute(real);
        f(lp_file_time);
    } else {
        GetSystemTimeAsFileTime(lp_file_time);
    }
}

#[no_mangle]
pub static __imp_GetSystemTimePreciseAsFileTime: unsafe extern "system" fn(*mut std::ffi::c_void) =
    GetSystemTimePreciseAsFileTime;

// =========================================================================
// 2. ProcessPrng (bcryptprimitives.dll -> advapi32 SystemFunction036)
// =========================================================================

#[no_mangle]
pub unsafe extern "system" fn ProcessPrng(pb_data: *mut u8, cb_data: usize) -> i32 {
    static REAL_FN: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
    static FALLBACK_FN: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
    static INITIALIZED: AtomicBool = AtomicBool::new(false);

    if !INITIALIZED.load(Ordering::Acquire) {
        // Tenta primeiro carregar de bcryptprimitives.dll (Windows 10/11)
        let h_bcrypt = LoadLibraryA(b"bcryptprimitives.dll\0".as_ptr());
        if !h_bcrypt.is_null() {
            let proc = GetProcAddress(h_bcrypt, b"ProcessPrng\0".as_ptr());
            if !proc.is_null() {
                REAL_FN.store(proc, Ordering::Release);
            }
        }

        // Se falhar ou para Windows 7/8, carrega SystemFunction036 (RtlGenRandom) de advapi32.dll
        let h_advapi = LoadLibraryA(b"advapi32.dll\0".as_ptr());
        if !h_advapi.is_null() {
            let proc = GetProcAddress(h_advapi, b"SystemFunction036\0".as_ptr());
            if !proc.is_null() {
                FALLBACK_FN.store(proc, Ordering::Release);
            }
        }

        INITIALIZED.store(true, Ordering::Release);
    }

    let real = REAL_FN.load(Ordering::Acquire);
    if !real.is_null() {
        let f: unsafe extern "system" fn(*mut u8, usize) -> i32 = std::mem::transmute(real);
        return f(pb_data, cb_data);
    }

    let fallback = FALLBACK_FN.load(Ordering::Acquire);
    if !fallback.is_null() {
        let f: unsafe extern "system" fn(*mut std::ffi::c_void, u32) -> u8 =
            std::mem::transmute(fallback);
        let mut remaining = cb_data;
        let mut curr = pb_data;
        while remaining > 0 {
            let chunk = std::cmp::min(remaining, u32::MAX as usize) as u32;
            if f(curr as *mut std::ffi::c_void, chunk) == 0 {
                return 0;
            }
            curr = curr.add(chunk as usize);
            remaining -= chunk as usize;
        }
        return 1;
    }

    0
}

#[no_mangle]
pub static __imp_ProcessPrng: unsafe extern "system" fn(*mut u8, usize) -> i32 = ProcessPrng;

// =========================================================================
// 3. WaitOnAddress, WakeByAddressAll, WakeByAddressSingle
// =========================================================================

#[no_mangle]
pub unsafe extern "system" fn WaitOnAddress(
    address: *mut std::ffi::c_void,
    compare_address: *mut std::ffi::c_void,
    address_size: usize,
    dw_milliseconds: u32,
) -> i32 {
    static REAL_FN: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
    static INITIALIZED: AtomicBool = AtomicBool::new(false);

    if !INITIALIZED.load(Ordering::Acquire) {
        // Tenta kernel32.dll (Windows 8+)
        let h_kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        if !h_kernel32.is_null() {
            let proc = GetProcAddress(h_kernel32, b"WaitOnAddress\0".as_ptr());
            if !proc.is_null() {
                REAL_FN.store(proc, Ordering::Release);
            }
        }
        // Se não estiver em kernel32, tenta api-ms-win-core-synch-l1-2-0.dll
        if REAL_FN.load(Ordering::Relaxed).is_null() {
            let h_synch = LoadLibraryA(b"api-ms-win-core-synch-l1-2-0.dll\0".as_ptr());
            if !h_synch.is_null() {
                let proc = GetProcAddress(h_synch, b"WaitOnAddress\0".as_ptr());
                if !proc.is_null() {
                    REAL_FN.store(proc, Ordering::Release);
                }
            }
        }
        INITIALIZED.store(true, Ordering::Release);
    }

    let real = REAL_FN.load(Ordering::Acquire);
    if !real.is_null() {
        let f: unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, usize, u32) -> i32 =
            std::mem::transmute(real);
        return f(address, compare_address, address_size, dw_milliseconds);
    }

    // Fallback Windows 7 com SRWLock e ConditionVariable
    fallback_wait_on_address(address, compare_address, address_size, dw_milliseconds)
}

#[no_mangle]
pub static __imp_WaitOnAddress: unsafe extern "system" fn(
    *mut std::ffi::c_void,
    *mut std::ffi::c_void,
    usize,
    u32,
) -> i32 = WaitOnAddress;

#[no_mangle]
pub unsafe extern "system" fn WakeByAddressSingle(address: *mut std::ffi::c_void) {
    static REAL_FN: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
    static INITIALIZED: AtomicBool = AtomicBool::new(false);

    if !INITIALIZED.load(Ordering::Acquire) {
        let h_kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        if !h_kernel32.is_null() {
            let proc = GetProcAddress(h_kernel32, b"WakeByAddressSingle\0".as_ptr());
            if !proc.is_null() {
                REAL_FN.store(proc, Ordering::Release);
            }
        }
        INITIALIZED.store(true, Ordering::Release);
    }

    let real = REAL_FN.load(Ordering::Acquire);
    if !real.is_null() {
        let f: unsafe extern "system" fn(*mut std::ffi::c_void) = std::mem::transmute(real);
        f(address);
    } else {
        fallback_wake_by_address_single(address);
    }
}

#[no_mangle]
pub static __imp_WakeByAddressSingle: unsafe extern "system" fn(*mut std::ffi::c_void) =
    WakeByAddressSingle;

#[no_mangle]
pub unsafe extern "system" fn WakeByAddressAll(address: *mut std::ffi::c_void) {
    static REAL_FN: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
    static INITIALIZED: AtomicBool = AtomicBool::new(false);

    if !INITIALIZED.load(Ordering::Acquire) {
        let h_kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        if !h_kernel32.is_null() {
            let proc = GetProcAddress(h_kernel32, b"WakeByAddressAll\0".as_ptr());
            if !proc.is_null() {
                REAL_FN.store(proc, Ordering::Release);
            }
        }
        INITIALIZED.store(true, Ordering::Release);
    }

    let real = REAL_FN.load(Ordering::Acquire);
    if !real.is_null() {
        let f: unsafe extern "system" fn(*mut std::ffi::c_void) = std::mem::transmute(real);
        f(address);
    } else {
        fallback_wake_by_address_all(address);
    }
}

#[no_mangle]
pub static __imp_WakeByAddressAll: unsafe extern "system" fn(*mut std::ffi::c_void) =
    WakeByAddressAll;

// =========================================================================
// Implementação do Fallback Windows 7 para WaitOnAddress via SRWLock/CV
// =========================================================================

#[derive(Copy, Clone)]
struct SyncBucket {
    lock: *mut std::ffi::c_void, // SRWLOCK inicializado com 0/NULL
    cv: *mut std::ffi::c_void,   // CONDITION_VARIABLE inicializado com 0/NULL
}

static mut BUCKETS: [SyncBucket; 64] = [SyncBucket {
    lock: std::ptr::null_mut(),
    cv: std::ptr::null_mut(),
}; 64];

#[inline]
unsafe fn get_bucket(address: *mut std::ffi::c_void) -> *mut SyncBucket {
    let idx = ((address as usize) >> 3) & 63;
    &raw mut BUCKETS[idx]
}

unsafe fn fallback_wait_on_address(
    address: *mut std::ffi::c_void,
    compare_address: *mut std::ffi::c_void,
    address_size: usize,
    dw_milliseconds: u32,
) -> i32 {
    let bucket = get_bucket(address);
    AcquireSRWLockExclusive(&raw mut (*bucket).lock as *mut _);

    let matches = match address_size {
        1 => *(address as *const u8) == *(compare_address as *const u8),
        2 => *(address as *const u16) == *(compare_address as *const u16),
        4 => *(address as *const u32) == *(compare_address as *const u32),
        8 => *(address as *const u64) == *(compare_address as *const u64),
        _ => libc_memcmp(address, compare_address, address_size) == 0,
    };

    if !matches {
        ReleaseSRWLockExclusive(&raw mut (*bucket).lock as *mut _);
        return 1; // Conteúdo já mudou
    }

    let ok = SleepConditionVariableSRW(
        &raw mut (*bucket).cv as *mut _,
        &raw mut (*bucket).lock as *mut _,
        dw_milliseconds,
        0,
    );

    ReleaseSRWLockExclusive(&raw mut (*bucket).lock as *mut _);
    ok
}

unsafe fn fallback_wake_by_address_single(address: *mut std::ffi::c_void) {
    let bucket = get_bucket(address);
    WakeConditionVariable(&raw mut (*bucket).cv as *mut _);
}

unsafe fn fallback_wake_by_address_all(address: *mut std::ffi::c_void) {
    let bucket = get_bucket(address);
    WakeAllConditionVariable(&raw mut (*bucket).cv as *mut _);
}

unsafe fn libc_memcmp(s1: *mut std::ffi::c_void, s2: *mut std::ffi::c_void, n: usize) -> i32 {
    let p1 = s1 as *const u8;
    let p2 = s2 as *const u8;
    for i in 0..n {
        if *p1.add(i) != *p2.add(i) {
            return 1;
        }
    }
    0
}
