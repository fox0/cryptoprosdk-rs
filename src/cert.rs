use crate::cprocsp::{wchar_t, CertCloseStore, CertOpenSystemStoreW, HCERTSTORE};

pub struct CertStore {
    cert_store: HCERTSTORE,
}

impl CertStore {
    pub fn try_new<T: Into<String>>(store: T) -> Result<Self, ()> {
        let store_name = store.into().as_ptr() as *const wchar_t;
        let cert_store = unsafe { CertOpenSystemStoreW(0, store_name) };
        if cert_store.is_null() {
            // let error_number = GetLastError();
            return Err(());
        }
        Ok(Self { cert_store })
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        let _r = unsafe { CertCloseStore(self.cert_store, 0) };
    }
}
