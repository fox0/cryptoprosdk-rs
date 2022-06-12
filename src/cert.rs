use std::ffi::CString;
use std::os::raw::{c_uint, c_void};

use crate::cprocsp::{
    CertCloseStore, CertFindCertificateInStore, CertOpenSystemStoreA, CryptStringToBinaryA,
    CERT_NAME_STR_CRLF_FLAG, CERT_X500_NAME_STR, CRYPT_STRING_HEX, HCERTSTORE, PKCS_7_ASN_ENCODING,
    X509_ASN_ENCODING,
};

// https://cpdn.cryptopro.ru/content/capilite/html/group___store_func.html
pub struct CertStore {
    cert_store: HCERTSTORE,
}

impl CertStore {
    pub fn try_new<T: Into<Vec<u8>>>(store: T) -> Result<Self, ()> {
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

        todo!()
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        let _r = unsafe { CertCloseStore(self.cert_store, 0) };
    }
}

unsafe fn get_hash_from_hex<T: Into<String>>(thumbprint: T) -> Result<Vec<u8>, ()> {
    let thumbprint = thumbprint.into();
    let thumbprint_len = thumbprint.len() as c_uint;
    let thumbprint = CString::new(thumbprint).unwrap();
    let thumbprint = thumbprint.as_ptr(); // as *const wchar_t;

    let mut result_len: c_uint = 20;
    let mut result: Vec<u8> = Vec::with_capacity(result_len as usize);
    result.set_len(result_len as usize);
    // dbg!(&result);

    let r = CryptStringToBinaryA(
        thumbprint,
        thumbprint_len,
        CRYPT_STRING_HEX,
        result.as_mut_ptr(),
        &mut result_len,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    if r == 0 {
        return Err(());
    };

    // dbg!(&result);
    // dbg!(&result_len);
    result.set_len(result_len as usize);
    Ok(result)
}

/*
    HCERTSTORE hStoreHandle;
    PCCERT_CONTEXT pCertContext = NULL;

    BYTE pDest[20];
    DWORD nOutLen = 20;

    if (!CryptStringToBinary(thumbprint, 40, CRYPT_STRING_HEX, pDest, &nOutLen, 0, 0)) {
        PyErr_SetString(PyExc_Exception, "CryptStringToBinary failed.");
        return NULL;
    }

    CRYPT_HASH_BLOB para;
    para.pbData = pDest;
    para.cbData = nOutLen;

    hStoreHandle = CertOpenSystemStore(0, storeName);
    pCertContext = CertFindCertificateInStore(hStoreHandle, MY_ENCODING_TYPE, 0, CERT_FIND_HASH, &para, NULL);

    if (!pCertContext) {
        CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
        PyErr_SetString(CertDoesNotExist, "Could not find the desired certificate.");
        return NULL;
    }

    PyObject * certInfo = GetCertInfo(pCertContext);

    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);

    return certInfo;
*/

#[cfg(test)]
mod tests {
    use crate::cert::get_hash_from_hex;
    use crate::CertStore;

    fn get_cert_store_my() -> CertStore {
        CertStore::try_new("MY").unwrap()
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
    fn test_get_cert_by_thumbprint() {
        let store = get_cert_store_my();
        store
            .find_certificate_by_thumbprint("046255290b0eb1cdd1797d9ab8c81f699e3687f3")
            .unwrap();
    }
}
