use std::os::raw::{c_uchar, c_uint, c_void};

use crate::cprocsp::{
    wchar_t, CertCloseStore, CertFindCertificateInStore, CertOpenSystemStoreW,
    CryptStringToBinaryW, CERT_NAME_STR_CRLF_FLAG, CERT_X500_NAME_STR, CRYPT_STRING_HEX,
    HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

// https://cpdn.cryptopro.ru/content/capilite/html/group___store_func.html
pub struct CertStore {
    cert_store: HCERTSTORE,
}

impl CertStore {
    pub fn try_new<T: Into<String>>(store: T) -> Result<Self, ()> {
        let store = store.into().as_ptr() as *const wchar_t; //todo?
        let cert_store = unsafe { CertOpenSystemStoreW(0, store) };
        if cert_store.is_null() {
            // let error_number = GetLastError();
            return Err(());
        }
        Ok(Self { cert_store })
    }

    pub fn find_certificate_by_subject<T: Into<String>>(&self, subject: T) -> Option<()> {
        let subject = subject.into().as_ptr() as *const c_void;
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
            return None;
        }
        todo!()
    }

    pub fn find_certificate_by_thumbprint<T: Into<String>>(&self, thumbprint: T) -> Option<()> {
        let thumbprint = thumbprint.into();
        let thumbprint_len = thumbprint.len() as c_uint;
        let thumbprint = thumbprint.as_ptr() as *const wchar_t;

        unsafe {
            let p: *mut [c_uchar; 20];
            let r = CryptStringToBinaryW(
                thumbprint,
                thumbprint_len,
                CRYPT_STRING_HEX, //
                (),
                (),
                (),
                (),
            );
            if !r {
                return None;
            };
        }

        todo!()
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        let _r = unsafe { CertCloseStore(self.cert_store, 0) };
    }
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
