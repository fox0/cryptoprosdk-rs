#[allow(unused)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
// #[allow(improper_ctypes)]
mod cprocsp;

use std::mem::{size_of, MaybeUninit};
use std::os::raw::{c_int, c_uchar, c_uint};
use std::ptr::null;

use crate::cprocsp::{
    szOID_CP_GOST_R3411, CadesSignMessage, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    _CADES_SIGN_MESSAGE_PARA, _CADES_SIGN_PARA, _CERT_CONTEXT, _CRYPTOAPI_BLOB,
    _CRYPT_ALGORITHM_IDENTIFIER, _CRYPT_SIGN_MESSAGE_PARA,
};

struct CryptoBlob(_CRYPTOAPI_BLOB);

// impl Drop for CryptoBlob {
//     fn drop(&mut self) {
//         // SAFETY: the caller must guarantee that `self` is initialized
//         let _ret = unsafe { CadesFreeBlob(0, 1) };
//     }
// }

// https://docs.cryptopro.ru/cades/reference/cadesc/cadesc-samples/samplesimplifiedapisign
fn sign(
    sign_message_para: _CRYPT_SIGN_MESSAGE_PARA,
    cades_sign_para: Option<_CADES_SIGN_PARA>,
    message: String,
) -> Result<Vec<u8>, ()> {
    let mut sign_message_para = sign_message_para;
    // Структура, задаваемая в качестве параметра функции CadesSignMessage.
    let mut arg = _CADES_SIGN_MESSAGE_PARA {
        dwSize: size_of::<_CADES_SIGN_MESSAGE_PARA>() as u32,
        pSignMessagePara: &mut sign_message_para,
        pCadesSignPara: match cades_sign_para {
            None => null::<_CADES_SIGN_PARA>() as *mut _CADES_SIGN_PARA,
            Some(mut v) => &mut v,
        },
    };
    let detached = 1 as c_int; //true
    let mut mess = message.as_ptr() as *const c_uchar;
    let mut mess_len = message.len() as c_uint;
    let mut signed_blob: MaybeUninit<CryptoBlob> = MaybeUninit::zeroed();
    let mut s = signed_blob.as_mut_ptr() as *mut _CRYPTOAPI_BLOB;
    let r = unsafe { CadesSignMessage(&mut arg, detached, 1, &mut mess, &mut mess_len, &mut s) };
    if r != 0 {
        return Err(());
    }

    // SAFETY: is initialized
    let _signed_blob = unsafe { signed_blob.assume_init() };

    let result: Vec<u8> = vec![];
    //todo copy
    Ok(result)
}

fn main() {
    // let p = _CADES_SIGN_PARA {
    //     dwSize: (),
    //     dwCadesType: (),
    //     pSignerCert: (),
    //     szHashAlgorithm: (),
    //     hAdditionalStore: (),
    //     pTspConnectionPara: (),
    //     pProxyPara: (),
    //     pCadesExtraPara: ()
    // }
    //
    // let mut p_context = _CERT_CONTEXT {
    //     dwCertEncodingType: (),
    //     pbCertEncoded: (),
    //     cbCertEncoded: (),
    //     pCertInfo: (),
    //     hCertStore: (),
    // };
    //
    // // https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_sign_message_para
    // let sign_message_para = _CRYPT_SIGN_MESSAGE_PARA {
    //     cbSize: size_of::<_CRYPT_SIGN_MESSAGE_PARA>(),
    //     dwMsgEncodingType: X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
    //     pSigningCert: &mut p_context,
    //     HashAlgorithm: _CRYPT_ALGORITHM_IDENTIFIER {
    //         pszObjId: szOID_CP_GOST_R3411 as *mut c_char,
    //         // Parameters: null::<_CRYPTOAPI_BLOB>(),
    //         Parameters: _CRYPTOAPI_BLOB { cbData: (), pbData: () }
    //     },
    //     pvHashAuxInfo: (),
    //     cMsgCert: (),
    //     rgpMsgCert: (),
    //     cMsgCrl: (),
    //     rgpMsgCrl: (),
    //     cAuthAttr: (),
    //     rgAuthAttr: (),
    //     cUnauthAttr: (),
    //     rgUnauthAttr: (),
    //     dwFlags: (),
    //     dwInnerContentType: (),
    // };
    //
    // let result = sign(sign_message_para, None, "Trixie is Best Pony!".to_string()).unwrap();
    // dbg!(result);
}
