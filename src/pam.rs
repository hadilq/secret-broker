//! `secret-broker pam-check SERVICE USER`: a tiny PAM client the broker runs
//! as a separate process for PAM-based quick approval (fingerprint, ...), so
//! PAM modules never load into the process that holds the secrets.
//!
//! The conversation answers informational messages (shown on stderr) and
//! refuses every prompt: methods that need typed input are not supported
//! here, which keeps passwords out of this path entirely.

use std::ffi::{c_char, c_int, c_void, CStr, CString};

const PAM_SUCCESS: c_int = 0;
const PAM_BUF_ERR: c_int = 5;
const PAM_CONV_ERR: c_int = 19;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;
#[cfg(target_os = "linux")]
const PAM_SILENT: c_int = 0x8000;
/// OpenPAM (macOS) uses a different bit than Linux-PAM.
#[cfg(target_os = "macos")]
const PAM_SILENT: c_int = i32::MIN; // 0x8000_0000

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
extern "C" {
    fn pam_start(
        service: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        pamh: *mut *mut c_void,
    ) -> c_int;
    fn pam_authenticate(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_acct_mgmt(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(pamh: *mut c_void, status: c_int) -> c_int;
    fn pam_strerror(pamh: *mut c_void, errnum: c_int) -> *const c_char;
}

extern "C" fn conversation(
    n: c_int,
    msgs: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    _appdata: *mut c_void,
) -> c_int {
    let Ok(count) = usize::try_from(n) else {
        return PAM_CONV_ERR;
    };
    if count == 0 || msgs.is_null() || resp.is_null() {
        return PAM_CONV_ERR;
    }
    for i in 0..count {
        // SAFETY: Linux-PAM passes `n` valid message pointers in a contiguous
        // array (the Linux-PAM layout); i < n.
        let m = unsafe { *msgs.add(i) };
        if m.is_null() {
            return PAM_CONV_ERR;
        }
        // SAFETY: m points to a valid pam_message for the call's duration.
        let (style, text) = unsafe { ((*m).msg_style, (*m).msg) };
        match style {
            PAM_TEXT_INFO | PAM_ERROR_MSG => {
                if !text.is_null() {
                    // SAFETY: PAM message text is a NUL-terminated C string.
                    let t = unsafe { CStr::from_ptr(text) };
                    eprintln!("pam: {}", t.to_string_lossy());
                }
            }
            // Prompts (passwords, PINs): refused on purpose.
            _ => return PAM_CONV_ERR,
        }
    }
    // PAM frees the response array (and each resp) with free(3).
    // SAFETY: calloc returns zeroed memory or null; zeroed PamResponse means
    // resp = NULL, resp_retcode = 0, which is valid for info messages.
    let arr = unsafe { libc::calloc(count, std::mem::size_of::<PamResponse>()) };
    if arr.is_null() {
        return PAM_BUF_ERR;
    }
    // SAFETY: resp is a valid out-pointer supplied by PAM.
    unsafe {
        *resp = arr.cast();
    }
    PAM_SUCCESS
}

fn strerror(h: *mut c_void, r: c_int) -> String {
    // SAFETY: pam_strerror returns a static string for any error number.
    let s = unsafe { pam_strerror(h, r) };
    if s.is_null() {
        return format!("PAM error {r}");
    }
    // SAFETY: NUL-terminated static string.
    unsafe { CStr::from_ptr(s) }.to_string_lossy().into_owned()
}

/// Authenticate `user` with PAM `service`. Ok(()) only on PAM_SUCCESS for
/// both auth and account checks.
pub fn check(service: &str, user: &str) -> Result<(), String> {
    let svc = CString::new(service).map_err(|_| "bad service name".to_string())?;
    let usr = CString::new(user).map_err(|_| "bad user name".to_string())?;
    let conv = PamConv {
        conv: conversation,
        appdata_ptr: std::ptr::null_mut(),
    };
    let mut h: *mut c_void = std::ptr::null_mut();
    // SAFETY: all pointers are valid; conv outlives the PAM handle (pam_end
    // is called before returning).
    let r = unsafe { pam_start(svc.as_ptr(), usr.as_ptr(), &conv, &mut h) };
    if r != PAM_SUCCESS || h.is_null() {
        return Err(format!("pam_start({service}): error {r}"));
    }
    // SAFETY: h is a live handle from pam_start.
    let mut r = unsafe { pam_authenticate(h, PAM_SILENT) };
    if r == PAM_SUCCESS {
        // SAFETY: as above.
        r = unsafe { pam_acct_mgmt(h, PAM_SILENT) };
    }
    let msg = strerror(h, r);
    // SAFETY: h is live; ends the transaction and frees it.
    unsafe {
        pam_end(h, r);
    }
    if r == PAM_SUCCESS {
        Ok(())
    } else {
        Err(msg)
    }
}
