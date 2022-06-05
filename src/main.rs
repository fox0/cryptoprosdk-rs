#[allow(unused)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
// #[allow(improper_ctypes)]
mod cprocsp;

use std::mem::{size_of, MaybeUninit};
use std::os::raw::{c_uchar, c_uint};

use crate::cprocsp::{CadesSignMessage, _CADES_SIGN_MESSAGE_PARA, _CRYPTOAPI_BLOB};

struct CryptoBlob(_CRYPTOAPI_BLOB);

// impl Drop for CryptoBlob {
//     fn drop(&mut self) {
//         // SAFETY: the caller must guarantee that `self` is initialized
//         let _ret = unsafe { CadesFreeBlob(0, 1) };
//     }
// }

// https://docs.cryptopro.ru/cades/reference/cadesc/cadesc-samples/samplesimplifiedapisign
unsafe fn sign(para: &mut _CADES_SIGN_MESSAGE_PARA, message: &str) -> Result<Vec<u8>, ()> {
    let mut signed_blob: MaybeUninit<CryptoBlob> = MaybeUninit::zeroed();
    let mut s = signed_blob.as_mut_ptr() as *mut _CRYPTOAPI_BLOB;

    let mut message_len: c_uint = message.len() as c_uint;
    let mut message: *const c_uchar = message.as_ptr() as *const c_uchar;
    let r = CadesSignMessage(
        &mut *para,
        1, //true
        1, // true?
        &mut message,
        &mut message_len,
        &mut s,
    );
    if r != 0 {
        return Err(());
    }
    let _signed_blob = signed_blob.assume_init();

    let result: Vec<u8> = vec![];
    //todo copy
    Ok(result)
}

fn main() {
    // let p_context = CERT_CONTEXT {
    //     dwCertEncodingType: (),
    //     pbCertEncoded: (),
    //     cbCertEncoded: (),
    //     pCertInfo: (),
    //     hCertStore: (),
    // };
    //
    // let sign_para = CRYPT_SIGN_MESSAGE_PARA {
    //     cbSize: size_of::<CRYPT_SIGN_MESSAGE_PARA>(),
    //     dwMsgEncodingType: X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
    //     pSigningCert: *p_context,
    //     HashAlgorithm: szOID_OIWSEC_sha1.clone(),
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
    // let para = CADES_SIGN_MESSAGE_PARA {
    //     dwSize: size_of::<CADES_SIGN_MESSAGE_PARA>(),
    //     pSignMessagePara: *sign_para,
    //     pCadesSignPara: (),
    // };

    // let result = sign("Trixie is Best Pony!").unwrap();
    // dbg!(result);
}
