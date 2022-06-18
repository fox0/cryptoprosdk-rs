use std::ffi::CString;
use std::fmt::{Debug, Formatter};
use std::os::raw::{c_char, c_int, c_uint, c_void};

#[link(name = "wrap")]
extern "C" {
    fn get_last_error() -> c_uint;
    fn open_store(store_name: *const c_char) -> *mut c_void;
    fn close_store(store: *mut c_void) -> c_int;
    fn find_certificate_by_thumbprint(store: *mut c_void, thumbprint: *const c_char)
        -> *mut c_void;
}

pub struct ErrorCode {
    code: c_uint,
}

impl ErrorCode {
    pub fn new() -> Self {
        Self {
            code: unsafe { get_last_error() },
        }
    }
}

impl Debug for ErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:#x}", self.code)
    }
}

#[derive(Debug)]
pub struct CertContext {
    inner: *mut c_void,
}

/// Хранилище сертификатов
#[derive(Debug)]
pub struct CertStore {
    inner: *mut c_void,
}

impl CertStore {
    pub fn try_new<T: Into<String>>(store_name: T) -> Result<Self, ErrorCode> {
        let store_name = store_name.into();
        //переменная должна жить достаточно долго
        let store_name = CString::new(store_name).unwrap();

        let inner = unsafe { open_store(store_name.as_ptr()) };
        if inner.is_null() {
            Err(ErrorCode::new())
        } else {
            Ok(Self { inner })
        }
    }

    pub fn find_certificate<T: Into<String>>(
        &self,
        thumbprint: T,
    ) -> Result<CertContext, ErrorCode> {
        let thumbprint = thumbprint.into();
        let thumbprint = CString::new(thumbprint).unwrap();

        let inner = unsafe { find_certificate_by_thumbprint(self.inner, thumbprint.as_ptr()) };
        if inner.is_null() {
            Err(ErrorCode::new())
        } else {
            Ok(CertContext { inner })
        }
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        let _r = unsafe { close_store(self.inner) };
    }
}

#[cfg(test)]
mod tests {
    use crate::cert::CertStore;

    #[test]
    fn test_cert_store_open_my() {
        let _ = CertStore::try_new("MY").unwrap();
    }

    // /opt/cprocsp/bin/amd64/certmgr certmgr --list --thumbprint 046255290b0eb1cdd1797d9ab8c81f699e3687f3
    #[test]
    fn test_get_cert_by_thumbprint() {
        CertStore::try_new("MY")
            .unwrap()
            .find_certificate("046255290b0eb1cdd1797d9ab8c81f699e3687f3")
            .unwrap();
    }

    #[test]
    fn test_get_cert_by_thumbprint2() {
        CertStore::try_new("MY")
            .unwrap()
            .find_certificate("8cae88bbfd404a7a53630864f9033606e1dc45e2")
            .unwrap();
    }

    #[test]
    fn test_get_cert_by_thumbprint3() {
        let r = CertStore::try_new("MY")
            .unwrap()
            .find_certificate("0cae88bbfd404a7a53630864f9033606e1dc45e2");
        dbg!(&r);
        assert!(r.is_err());
    }
}
