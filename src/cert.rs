use std::ffi::CString;
use std::os::raw::{c_uint, c_void};

use crate::cprocsp::{
    CertCloseStore, CertFindCertificateInStore, CertOpenSystemStoreA, CryptStringToBinaryA,
    CERT_FIND_HASH, CERT_NAME_STR_CRLF_FLAG, CERT_X500_NAME_STR, CRYPT_STRING_HEX, HCERTSTORE,
    PKCS_7_ASN_ENCODING, X509_ASN_ENCODING, _CRYPTOAPI_BLOB,
};

type PARA = _CRYPTOAPI_BLOB;

impl From<Vec<u8>> for PARA {
    fn from(mut value: Vec<u8>) -> Self {
        Self {
            cbData: value.len() as c_uint,
            pbData: value.as_mut_ptr(),
        }
    }
}

// https://cpdn.cryptopro.ru/content/capilite/html/group___store_func.html
pub struct CertStore {
    cert_store: HCERTSTORE,
}

impl CertStore {
    pub fn try_new<T: Into<String>>(store: T) -> Result<Self, ()> {
        let store = store.into();
        let store = CString::new(store).unwrap();
        let store = store.as_ptr(); // as *const wchar_t;

        let cert_store = unsafe { CertOpenSystemStoreA(0, store) };
        if cert_store.is_null() {
            // let error_number = GetLastError();
            return Err(());
        }
        Ok(Self { cert_store })
    }

    pub fn find_certificate_by_subject<T: Into<String>>(&self, subject: T) -> Result<(), ()> {
        let subject = subject.into();
        let subject = CString::new(subject).unwrap();
        let subject = subject.as_ptr() as *const c_void;

        let cert_context = unsafe {
            CertFindCertificateInStore(
                self.cert_store,
                PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                0,
                CERT_X500_NAME_STR | CERT_NAME_STR_CRLF_FLAG,
                subject,
                std::ptr::null(),
            )
        };
        if cert_context.is_null() {
            return Err(());
        }
        todo!()
    }

    pub fn find_certificate_by_thumbprint<T: Into<String>>(&self, thumbprint: T) -> Result<(), ()> {
        let hash = unsafe { get_hash_from_hex(thumbprint)? };
        let mut para: PARA = hash.into();
        let para = &mut para as *mut _ as *const c_void;

        let cert_context = unsafe {
            CertFindCertificateInStore(
                self.cert_store,
                PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                0,
                CERT_FIND_HASH,
                para,
                std::ptr::null(),
            )
        };
        if cert_context.is_null() {
            return Err(());
        }
        todo!()
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        let _r = unsafe { CertCloseStore(self.cert_store, 0) };
    }
}

/// ```
/// let r = unsafe { get_hash_from_hex("046255290b0eb1cdd1797d9ab8c81f699e3687f3").unwrap() };
/// assert_eq!(r, [4, 98, 85, 41, 11, 14, 177, 205, 209, 121, 125, 154, 184, 200, 31, 105, 158, 54, 135, 243]);
/// ```
unsafe fn get_hash_from_hex<T: Into<String>>(thumbprint: T) -> Result<Vec<u8>, ()> {
    let thumbprint = thumbprint.into();
    let thumbprint_len = thumbprint.len() as c_uint;
    let thumbprint = CString::new(thumbprint).unwrap();
    let thumbprint = thumbprint.as_ptr();

    let mut result_len: c_uint = 20;
    let mut result: Vec<u8> = Vec::with_capacity(result_len as usize);
    result.set_len(result_len as usize);

    let r = CryptStringToBinaryA(
        thumbprint,
        thumbprint_len,
        CRYPT_STRING_HEX,
        result.as_mut_ptr(),
        &mut result_len,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    if r == 0 || result_len == 0 {
        return Err(());
    }

    result.set_len(result_len as usize);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::cert::get_hash_from_hex;
    use crate::CertStore;

    fn get_cert_store_my() -> CertStore {
        CertStore::try_new("My").unwrap()
    }

    #[test]
    fn test_cert_store_open_my() {
        let _ = get_cert_store_my();
    }

    // /opt/cprocsp/bin/amd64/certmgr -inst -store MY -f tests/certs/
    #[test]
    #[ignore]
    fn test_get_cert_by_subject() {
        let store = get_cert_store_my();
        store.find_certificate_by_subject("E=support@cryptopro.ru, C=RU, L=Moscow, O=CRYPTO-PRO LLC, CN=CRYPTO-PRO Test Center 2").unwrap();
    }

    #[test]
    fn test_get_cert_by_thumbprint() {
        let store = get_cert_store_my();
        store
            .find_certificate_by_thumbprint("046255290b0eb1cdd1797d9ab8c81f699e3687f3")
            .unwrap();
    }

    #[test]
    fn test_get_cert_by_thumbprint2() {
        let store = get_cert_store_my();
        store
            .find_certificate_by_thumbprint("8cae88bbfd404a7a53630864f9033606e1dc45e2")
            .unwrap();
    }

    #[test]
    fn test_get_hash_from_hex() {
        let r = unsafe { get_hash_from_hex("046255290b0eb1cdd1797d9ab8c81f699e3687f3").unwrap() };
        let lst = [
            4, 98, 85, 41, 11, 14, 177, 205, 209, 121, 125, 154, 184, 200, 31, 105, 158, 54, 135,
            243,
        ];
        assert_eq!(r.len(), 20);
        assert_eq!(r, lst)
    }

    #[test]
    fn test_get_hash_from_hex2() {
        let r = unsafe { get_hash_from_hex("0x046255290b0eb1cdd1797d9ab8c81f699e3687f3") };
        assert!(r.is_err());
    }
}
