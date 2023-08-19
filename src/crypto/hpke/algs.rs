#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct Kem(pub(crate) u16);

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct Kdf(pub(crate) u16);

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct Aead(pub(crate) u16);
