#[cfg(test)]
mod tests {
    use cryptoprosdk_rs::get_cert_by_subject;

    #[test]
    fn get_cert_by_subject1() {
        let _ = get_cert_by_subject("MY", "pycryptoprosdk");
    }
}
