use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

#[link(name = "wrap")]
extern "C" {
    fn open_store(store_name: *const c_char) -> *mut c_void;
    fn close_store(store: *mut c_void) -> c_int;
    fn find_certificate_by_thumbprint(store: *mut c_void, thumbprint: *const c_char)
        -> *mut c_void;
}

pub struct CertContext {
    inner: *mut c_void,
}

/// Хранилище сертификатов
pub struct CertStore {
    inner: *mut c_void,
}

impl CertStore {
    pub fn try_new<T: Into<String>>(store_name: T) -> Option<Self> {
        let store_name = store_name.into();
        //переменная должна жить достаточно долго
        let store_name = CString::new(store_name).unwrap();

        let inner = unsafe { open_store(store_name.as_ptr()) };
        if inner.is_null() {
            None
        } else {
            Some(Self { inner })
        }
    }

    pub fn find_certificate<T: Into<String>>(&self, thumbprint: T) -> Option<CertContext> {
        let thumbprint = thumbprint.into();
        let thumbprint = CString::new(thumbprint).unwrap();

        let inner = unsafe { find_certificate_by_thumbprint(self.inner, thumbprint.as_ptr()) };
        if inner.is_null() {
            None
        } else {
            Some(CertContext { inner })
        }
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        let _r = unsafe { close_store(self.inner) };
    }
}

// // https://docs.cryptopro.ru/cades/reference/cadesc/cadesc-samples/samplesimplifiedapisign
// fn sign(
//     sign_message_para: _CRYPT_SIGN_MESSAGE_PARA,
//     cades_sign_para: Option<_CADES_SIGN_PARA>,
//     message: String,
// ) -> Result<Vec<u8>, ()> {
//     let mut sign_message_para = sign_message_para;
//     // Структура, задаваемая в качестве параметра функции CadesSignMessage.
//     let mut arg = _CADES_SIGN_MESSAGE_PARA {
//         dwSize: size_of::<_CADES_SIGN_MESSAGE_PARA>() as u32,
//         pSignMessagePara: &mut sign_message_para,
//         pCadesSignPara: cades_sign_para.as_mut_ptr(),
//     };
//     let detached = 1 as c_int; //true
//     let mut mess = message.as_ptr() as *const c_uchar;
//     let mut mess_len = message.len() as c_uint;
//     let mut signed_blob: MaybeUninit<CryptoBlob> = MaybeUninit::zeroed();
//     let mut s = signed_blob.as_mut_ptr() as *mut _CRYPTOAPI_BLOB;
//     let r = unsafe { CadesSignMessage(&mut arg, detached, 1, &mut mess, &mut mess_len, &mut s) };
//     if r != 0 {
//         return Err(());
//     }
//
//     // SAFETY: is initialized
//     let _signed_blob = unsafe { signed_blob.assume_init() };
//
//     let result: Vec<u8> = vec![];
//     //todo copy
//     Ok(result)
// }
//
// // fn main() {
// // let p = _CADES_SIGN_PARA {
// //     dwSize: (),
// //     dwCadesType: (),
// //     pSignerCert: (),
// //     szHashAlgorithm: (),
// //     hAdditionalStore: (),
// //     pTspConnectionPara: (),
// //     pProxyPara: (),
// //     pCadesExtraPara: ()
// // }
// //
// // let mut p_context = _CERT_CONTEXT {
// //     dwCertEncodingType: (),
// //     pbCertEncoded: (),
// //     cbCertEncoded: (),
// //     pCertInfo: (),
// //     hCertStore: (),
// // };
// //
// // // https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_sign_message_para
// // let sign_message_para = _CRYPT_SIGN_MESSAGE_PARA {
// //     cbSize: size_of::<_CRYPT_SIGN_MESSAGE_PARA>(),
// //     dwMsgEncodingType: X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
// //     pSigningCert: &mut p_context,
// //     HashAlgorithm: _CRYPT_ALGORITHM_IDENTIFIER {
// //         pszObjId: szOID_CP_GOST_R3411 as *mut c_char,
// //         // Parameters: null::<_CRYPTOAPI_BLOB>(),
// //         Parameters: _CRYPTOAPI_BLOB { cbData: (), pbData: () }
// //     },
// //     pvHashAuxInfo: (),
// //     cMsgCert: (),
// //     rgpMsgCert: (),
// //     cMsgCrl: (),
// //     rgpMsgCrl: (),
// //     cAuthAttr: (),
// //     rgAuthAttr: (),
// //     cUnauthAttr: (),
// //     rgUnauthAttr: (),
// //     dwFlags: (),
// //     dwInnerContentType: (),
// // };
// //
// // let result = sign(sign_message_para, None, "Trixie is Best Pony!".to_string()).unwrap();
// // dbg!(result);
// // }

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
}
