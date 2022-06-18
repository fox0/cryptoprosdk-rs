#include <stdarg.h>
#include <string.h>
#include <WinCryptEx.h>

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
    if (!store) {
        return NULL;
    }
    if (strlen(thumbprint) != 40) {
        return NULL;
    }

    unsigned int hash_len = 20;
    unsigned char hash[hash_len];
    int r = CryptStringToBinaryA(
            thumbprint,
            strlen(thumbprint),
            CRYPT_STRING_HEX,
            hash,
            &hash_len,
            NULL,
            NULL
    );
    if (r == 0) {
        return NULL;
    }

    DATA_BLOB para = {.cbData = hash_len, .pbData = hash};
    PCCERT_CONTEXT result = CertFindCertificateInStore(
            store,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            CERT_FIND_HASH,
            &para,
            NULL
    );
    return (void *) result;
}
