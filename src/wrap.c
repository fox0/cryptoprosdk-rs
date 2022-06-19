#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <WinCryptEx.h>
#include <cades.h>

#define CERT_ENCODING_TYPE PKCS_7_ASN_ENCODING | X509_ASN_ENCODING
#define CERT_HASH_ALGORITHM szOID_CP_GOST_R3411

#define PRINT_LAST_ERROR printf("[src/wrap.c:%d] error 0x%x\n", __LINE__, GetLastError())


unsigned int get_last_error() {
    return GetLastError();
}

void *open_store(const char *pszSubsystemProtocol) {
    if (strlen(pszSubsystemProtocol) == 0) {
        return NULL;
    }
    HCRYPTPROV hProv = 0;
    HCERTSTORE r = CertOpenSystemStoreA(hProv, pszSubsystemProtocol);
    if (!r) {
        PRINT_LAST_ERROR;
    }
    return r;
}

int close_store(void *hCertStore) {
    if (!hCertStore) {
        return 0;
    }
    const DWORD dwFlags = 0;
    return CertCloseStore(hCertStore, dwFlags);
}

void *find_certificate_by_thumbprint(void *hCertStore, const char *pszString) {
    const DWORD cchString = strlen(pszString);
    if (!hCertStore || cchString != 40) {
        return NULL;
    }
    const DWORD dwFlags = CRYPT_STRING_HEX;
    DWORD hashLen = 20;
    unsigned char pbBinary[hashLen];
    if (!CryptStringToBinaryA(pszString, cchString, dwFlags, pbBinary/*out*/, &hashLen/*out*/, NULL, NULL)) {
        PRINT_LAST_ERROR;
        return NULL;
    }
    const DWORD dwCertEncodingType = CERT_ENCODING_TYPE;
    const DWORD dwFindFlags = 0;
    const DWORD dwFindType = CERT_FIND_HASH;
    DATA_BLOB p = {
            .cbData = hashLen,
            .pbData = pbBinary
    };
    PCCERT_CONTEXT r = CertFindCertificateInStore(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, &p, NULL);
    if (!r) {
        PRINT_LAST_ERROR;
    }
    return (void *) r;
}

void sign(
        __in void *pSigningCert,
        __in const unsigned char *data,
        __in const unsigned int dataLen,
        __out unsigned char *result,
        __out unsigned int *resultLen
) {
    if (!pSigningCert || !data || dataLen == 0) {
        return;
    }
    CRYPT_SIGN_MESSAGE_PARA p2 = {
            .cbSize = sizeof(p2),
            .dwMsgEncodingType = CERT_ENCODING_TYPE,
            .pSigningCert = (PCCERT_CONTEXT) pSigningCert,
            .HashAlgorithm.pszObjId = CERT_HASH_ALGORITHM
    };
    CADES_SIGN_MESSAGE_PARA p = {
            .dwSize = sizeof(p),
            .pSignMessagePara = &p2
    };
    const BOOL fDetachedSignature = TRUE;
    const DWORD cToBeSigned = 1;
    const BYTE *rgpbToBeSigned[] = {&data[0]};
    DWORD rgcbToBeSigned[] = {dataLen};
    DATA_BLOB *r = 0;
    if (!CadesSignMessage(&p, fDetachedSignature, cToBeSigned, rgpbToBeSigned, rgcbToBeSigned, &r/*out*/)) {
        PRINT_LAST_ERROR;
        return;
    }

    for (size_t i = 0; i < r->cbData; i++) {
        printf("%d ", r->pbData[i]);
    }

//    std::vector < BYTE > message(r->cbData);
//    std::copy(r->pbData,
//              r->pbData + r->cbData, message.begin());
//
//    if (!CadesFreeBlob(r)) {
//        std::cout << "CadesFreeBlob() failed" << std::endl;
//        return empty;
//    }
}
