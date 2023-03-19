use std::ffi::CString;
use std::fmt::{Debug, Formatter};
use std::os::raw::{c_char, c_int, c_uchar, c_uint, c_ulonglong, c_void};

pub struct ErrorCode(c_uint);

/// Хранилище сертификатов
#[derive(Debug)]
#[repr(transparent)]
pub struct CertStore(*mut c_void);

/// Контекст сертификата
#[derive(Debug)]
#[repr(transparent)]
pub struct CertContext(*mut c_void);

// bindgen /opt/cprocsp/include/cpcsp/CSP_WinCrypt.h
#[repr(C)]
// #[derive(Debug, Copy, Clone)]
struct DataBlob {
    pub cb_data: c_uint,
    pub pb_data: *mut c_uchar,
}

#[derive(Debug)]
#[repr(transparent)]
struct Blob(*mut DataBlob);

#[link(name = "wrap")]
extern "C" {
    fn GetLastError() -> c_uint;
    fn CertOpenSystemStoreA(_: c_ulonglong, _: *const c_char) -> *mut c_void;
    fn CertCloseStore(_: *mut c_void, _: c_uint) -> c_int;
    fn CertFreeCertificateContext(_: *mut c_void) -> c_int;
    fn CadesFreeBlob(_: *mut DataBlob) -> c_int;
    fn wrapFindCertificateByThumbprint(_: *mut c_void, _: *const c_char) -> *mut c_void;
    fn wrapSign(_: *mut c_void, _: *const c_uchar, _: c_uint) -> *mut DataBlob;
}

impl ErrorCode {
    pub fn new() -> Self {
        Self(unsafe { GetLastError() })
    }
}

impl Debug for ErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "error {:#x}", self.0)
    }
}

macro_rules! try_new {
    ($t:ident, $value:ident) => {
        if !$value.is_null() {
            Ok($t($value))
        } else {
            Err(ErrorCode::new())
        }
    };
}

macro_rules! print_error {
    ($value:ident) => {
        if $value == 0 {
            eprintln!("{:?}", ErrorCode::new());
        }
    };
}

impl CertStore {
    pub fn new<T>(store_name: T) -> Result<Self, ErrorCode>
    where
        T: Into<String>,
    {
        let store_name = store_name.into();
        //переменная должна жить достаточно долго
        let store_name = CString::new(store_name).unwrap();
        let r = unsafe { CertOpenSystemStoreA(0, store_name.as_ptr()) };
        try_new!(Self, r)
    }

    pub fn find<T>(&self, thumbprint: T) -> Result<CertContext, ErrorCode>
    where
        T: Into<String>,
    {
        let thumbprint = thumbprint.into();
        let thumbprint = CString::new(thumbprint).unwrap();
        let r = unsafe { wrapFindCertificateByThumbprint(self.0, thumbprint.as_ptr()) };
        try_new!(CertContext, r)
    }
}

impl CertContext {
    /// Подписать сообщение отсоединённой подписью
    pub fn sign<T>(&self, data: T) -> Result<Vec<u8>, ErrorCode>
    where
        T: Into<Vec<u8>>,
    {
        let data = data.into();
        let r = unsafe { wrapSign(self.0, data.as_ptr(), data.len() as c_uint) };
        let blob = try_new!(Blob, r)?;
        Ok(blob.into())
    }
}

impl Into<Vec<u8>> for Blob {
    fn into(self) -> Vec<u8> {
        todo!()
        // let mut result_len: c_uint = 20;
        // let mut result: Vec<u8> = Vec::with_capacity(result_len as usize);
        // result.set_len(result_len as usize);
        //         c_func(result.as_mut_ptr(), &mut result_len);
        // for (size_t i = 0; i < r->cb_data; i++) {
        //     printf("%d ", r->pb_data[i]);
        // }
        //    std::vector < BYTE > message(r->cb_data);
        //    std::copy(r->pb_data,
        //              r->pb_data + r->cb_data, message.begin());
        //
        //    if (!CadesFreeBlob(r)) {
        //        std::cout << "CadesFreeBlob() failed" << std::endl;
        //        return empty;
        //    }
        //         result.set_len(result_len as usize);
        //         result
        //     }
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        // SAFETY: not null
        let r = unsafe { CertCloseStore(self.0, 0) };
        print_error!(r);
    }
}

impl Drop for CertContext {
    fn drop(&mut self) {
        // SAFETY: not null
        let r = unsafe { CertFreeCertificateContext(self.0) };
        print_error!(r);
    }
}

impl Drop for Blob {
    fn drop(&mut self) {
        // SAFETY: not null
        let r = unsafe { CadesFreeBlob(self.0) };
        print_error!(r);
    }
}

#[cfg(test)]
mod tests {
    use crate::cert::CertStore;

    #[test]
    fn test_cert_store_open_my() {
        let _ = CertStore::new("MY").unwrap();
    }

    // /opt/cprocsp/bin/amd64/certmgr certmgr --list --thumbprint 046255290b0eb1cdd1797d9ab8c81f699e3687f3
    #[test]
    fn test_get_cert_by_thumbprint() {
        CertStore::new("MY")
            .unwrap()
            .find("046255290b0eb1cdd1797d9ab8c81f699e3687f3")
            .unwrap();
    }

    #[test]
    fn test_get_cert_by_thumbprint2() {
        CertStore::new("MY")
            .unwrap()
            .find("8cae88bbfd404a7a53630864f9033606e1dc45e2")
            .unwrap();
    }

    #[test]
    fn test_get_cert_by_thumbprint3() {
        let r = CertStore::new("MY")
            .unwrap()
            .find("0cae88bbfd404a7a53630864f9033606e1dc45e2");
        dbg!(&r);
        assert!(r.is_err());
    }

    #[test]
    fn test_sign() {
        let cert = CertStore::new("MY")
            .unwrap()
            .find("046255290b0eb1cdd1797d9ab8c81f699e3687f3")
            .unwrap();
        let sign = cert.sign("123").unwrap();
        dbg!(sign);
    }
}
