mod cert;

use cert::CertStore;

fn main() {
    let _r = CertStore::try_new("MY").unwrap();
}
