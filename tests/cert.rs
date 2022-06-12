#[cfg(test)]
mod tests {
    use cryptoprosdk_rs::CertStore;

    fn get_cert_store_my() -> CertStore {
        CertStore::try_new("MY").unwrap()
    }

    #[test]
    fn cert_store_open_my() {
        let _ = get_cert_store_my();
    }

    // /opt/cprocsp/bin/amd64/certmgr -inst -store MY -f tests/certs/
    #[test]
    #[ignore]
    fn get_cert_by_subject() {
        let store = get_cert_store_my();
        store.find_certificate_by_subject("E=support@cryptopro.ru, C=RU, L=Moscow, O=CRYPTO-PRO LLC, CN=CRYPTO-PRO Test Center 2").unwrap();
    }

    #[test]

    fn get_cert_by_thumbprint() {
        let store = get_cert_store_my();
        store
            .find_certificate_by_thumbprint("046255290b0eb1cdd1797d9ab8c81f699e3687f3")
            .unwrap();
    }
}
