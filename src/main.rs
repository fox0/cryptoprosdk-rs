mod cert;

use cert::CertStore;

fn main() {
    let store = CertStore::new("MY").unwrap();
    let cert = store
        .find("046255290b0eb1cdd1797d9ab8c81f699e3687f3")
        .unwrap();
    let sign = cert.sign("123").unwrap();
    dbg!(sign);
}
