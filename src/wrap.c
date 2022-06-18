#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <WinCryptEx.h>
#include <cades.h>

#define CERT_ENCODING_TYPE PKCS_7_ASN_ENCODING | X509_ASN_ENCODING
#define CERT_HASH_ALGORITHM szOID_CP_GOST_R3411

unsigned int get_last_error() {
    return GetLastError();
}

void *open_store(const char *store_name) {
    if (strlen(store_name) == 0) {
        return NULL;
    }
    return CertOpenSystemStoreA(0, store_name);
}

int close_store(void *store) {
    if (!store) {
        return 0;
    }
    return CertCloseStore(store, 0);
}

void *find_certificate_by_thumbprint(void *store, const char *thumbprint) {
    if (!store || strlen(thumbprint) != 40) {
        return NULL;
    }

    unsigned int hash_len = 20;
    unsigned char hash[hash_len];
    if (!CryptStringToBinaryA(
            thumbprint,
            strlen(thumbprint),
            CRYPT_STRING_HEX,
            hash,
            &hash_len,
            NULL,
            NULL
    )) {
        return NULL;
    }

    DATA_BLOB para = {.cbData = hash_len, .pbData = hash};
    PCCERT_CONTEXT result = CertFindCertificateInStore(
            store,
            CERT_ENCODING_TYPE,
            0,
            CERT_FIND_HASH,
            &para,
            NULL
    );
    return (void *) result;
}

void sign(void *cert_context, const unsigned char *data) {
    CRYPT_SIGN_MESSAGE_PARA signPara = {sizeof(signPara)};
    signPara.dwMsgEncodingType = CERT_ENCODING_TYPE;
    signPara.pSigningCert = (PCCERT_CONTEXT) cert_context;
    signPara.HashAlgorithm.pszObjId = CERT_HASH_ALGORITHM;

    CADES_SIGN_MESSAGE_PARA para = {sizeof(para)};
    para.pSignMessagePara = &signPara;

    const BYTE *pbToBeSigned[] = {&data[0]};
    DWORD cbToBeSigned[] = {strlen((const char *) data)};

    PCRYPT_DATA_BLOB pSignedMessage = 0;
    if (!CadesSignMessage(
            &para,
            TRUE, // detached
            1,
            pbToBeSigned,
            cbToBeSigned,
            &pSignedMessage
    )) {
        //printf("error 0x%x\n", GetLastError());
        return;
    }

    for (size_t i = 0; i < pSignedMessage->cbData; i++) {
        printf("%d ", pSignedMessage->pbData[i]);
    }

//    std::vector < BYTE > message(pSignedMessage->cbData);
//    std::copy(pSignedMessage->pbData,
//              pSignedMessage->pbData + pSignedMessage->cbData, message.begin());
//
//    if (!CadesFreeBlob(pSignedMessage)) {
//        std::cout << "CadesFreeBlob() failed" << std::endl;
//        return empty;
//    }
}
