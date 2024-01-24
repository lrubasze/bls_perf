use sha3::{Digest, Keccak256};

/// Represents a 32-byte hash digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; Self::LENGTH]);

impl Hash {
    pub const LENGTH: usize = 32;

    pub fn lower_bytes<const N: usize>(&self) -> [u8; N] {
        self.0[(Self::LENGTH - N)..Self::LENGTH].try_into().unwrap()
    }
}

pub trait IsHash: AsRef<[u8]> + Sized + From<Hash> + Into<Hash> + AsRef<Hash> {
    fn as_bytes(&self) -> &[u8; Hash::LENGTH] {
        &<Self as AsRef<Hash>>::as_ref(self).0
    }

    fn as_slice(&self) -> &[u8] {
        &<Self as AsRef<Hash>>::as_ref(self).0
    }

    fn as_hash(&self) -> &Hash {
        <Self as AsRef<Hash>>::as_ref(self)
    }

    fn into_bytes(self) -> [u8; Hash::LENGTH] {
        self.into_hash().0
    }

    fn into_hash(self) -> Hash {
        self.into()
    }

    fn from_bytes(bytes: [u8; Hash::LENGTH]) -> Self {
        Hash(bytes).into()
    }

    fn from_hash(hash: Hash) -> Self {
        hash.into()
    }
}

impl IsHash for Hash {}

impl AsRef<Hash> for Hash {
    fn as_ref(&self) -> &Hash {
        self
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub fn keccak256_hash<T: AsRef<[u8]>>(data: T) -> Hash {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    Hash(hash.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbor::rust::str::FromStr;

    #[test]
    fn test_keccak256_hash() {
        let data = "Hello Radix";
        let hash = keccak256_hash(data);
        assert_eq!(
            hash,
            Hash::from_str("415942230ddb029416a4612818536de230d827cbac9646a0b26d9855a4c45587")
                .unwrap()
        );
    }
}
