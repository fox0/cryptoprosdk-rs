#[allow(clippy::wrong_self_convention)]
pub trait MaybeNull {
    type Item;

    fn as_mut_ptr(self) -> *mut Self::Item;
}

impl<T> MaybeNull for Option<T> {
    type Item = T;

    /// Вернуть ссылку на объект или null
    fn as_mut_ptr(self) -> *mut Self::Item {
        match self {
            Some(mut v) => &mut v,
            None => std::ptr::null_mut::<T>(),
        }
    }
}
