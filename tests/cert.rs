#[cfg(test)]
mod tests {
    use cryptoprosdk_rs::{get_cert_by_subject, CertStore};

    #[test]
    fn get_cert_by_subject1() {
        let store = CertStore::try_new("MY").unwrap();
        let _ = get_cert_by_subject(&store, "pycryptoprosdk");
    }
}
