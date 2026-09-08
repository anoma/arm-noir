use age::EncryptError;
use age::scrypt::Identity;
use age::scrypt::Recipient;
use age::secrecy::SecretString;
use alloy::primitives::Address;
use alloy::primitives::B512;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::PrivateKeySigner;
use bech32::Hrp;
use serde::Deserializer;
use serde::Serializer;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::marker::PhantomData;
use std::str::FromStr;
use k256::ecdsa::VerifyingKey;
use k256::PublicKey;
use k256::SecretKey;
use k256::schnorr::CryptoRngCore;
use alloy::primitives::keccak256;
use rand::Rng;

// Ethereum block height
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct BlockHeight(u64);

// Encrypted bytes
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(transparent)]
pub struct Encrypted<X>(
    #[serde(with = "alloy::hex")] Vec<u8>,
    #[serde(skip)] PhantomData<X>,
);

pub trait Bech32 : Sized {
    const HRP: &str;

    /// Helper to convert the key to a bech32m string
    fn to_bech32m(&self) -> String {
        let bytes = self.to_vec().unwrap();
        let hrp = Hrp::parse(Self::HRP).expect("Valid HRP");
        bech32::encode::<bech32::Bech32m>(hrp, &bytes).expect("Should encode safely")
    }

    fn to_vec(&self) -> std::io::Result<Vec<u8>>;

    fn from_slice(v: &[u8]) -> std::io::Result<Self>;
}

pub const VERIFYING_KEY_LEN: usize = 33;
pub const SECRET_KEY_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 33;
pub const SIGNING_KEY_LEN: usize = 32;
pub const NULLIFIER_KEY_LEN: usize = 32;
pub const NULLIFIER_KEY_COMMITMENT_LEN: usize = 32;

#[derive(Clone, Copy, Debug)]
pub struct NullifierKey(pub [u8; NULLIFIER_KEY_LEN]);

impl NullifierKey {
    /// Generate a nullifier key
    pub fn random(rng: &mut impl Rng) -> Self {
        let mut nk = [0u8; NULLIFIER_KEY_LEN];
        rng.fill(&mut nk);
        Self(nk)
    }
    /// Compute the commitment to the nullifier key
    pub fn commit(self) -> [u8; NULLIFIER_KEY_COMMITMENT_LEN] {
        keccak256(self.0).0
    }
}

fn write_bytes(dest: &mut [u8], offset: &mut usize, src: &[u8]) {
    let next_offset = *offset + src.len();
    dest[*offset..next_offset].copy_from_slice(src);
    *offset = next_offset;
}

fn read_bytes<const N: usize>(src: &[u8], offset: &mut usize) -> [u8; N] {
    let mut dest = [0u8; N];
    let next_offset = *offset + N;
    dest.copy_from_slice(&src[*offset..next_offset]);
    *offset = next_offset;
    dest
}

pub type NullifierKeyCommitment = [u8; NULLIFIER_KEY_COMMITMENT_LEN];

#[derive(Clone, Debug)]
pub struct ExtendedFullViewingKey {
    pub verifying_key: VerifyingKey,
    pub secret_key: SecretKey,
    pub nullifier_key_commitment: NullifierKeyCommitment,
}

impl ExtendedFullViewingKey {
    /// Convert to a payment address
    pub fn to_payment_address(&self) -> PaymentAddress {
        PaymentAddress {
            verifying_key: self.verifying_key,
            public_key: self.secret_key.public_key(),
            nullifier_key_commitment: self.nullifier_key_commitment,
        }
    }
}

impl Bech32 for ExtendedFullViewingKey {
    const HRP: &str = "zxviewtestsapling";

    fn to_vec(&self) -> std::io::Result<Vec<u8>> {
        let mut bytes = [0u8; VERIFYING_KEY_LEN + SECRET_KEY_LEN + NULLIFIER_KEY_COMMITMENT_LEN];
        let mut offset = 0;
        write_bytes(&mut bytes, &mut offset, &self.verifying_key.to_sec1_bytes());
        write_bytes(&mut bytes, &mut offset, &self.secret_key.to_bytes());
        write_bytes(&mut bytes, &mut offset, &self.nullifier_key_commitment);
        Ok(bytes.to_vec())
    }

    fn from_slice(v: &[u8]) -> std::io::Result<Self> {
        if v.len() != VERIFYING_KEY_LEN + SECRET_KEY_LEN + NULLIFIER_KEY_COMMITMENT_LEN {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "unexpected length for ExtendedFullViewingKey",
            ));
        }
        let mut offset = 0;
        let vk = VerifyingKey::from_sec1_bytes(&read_bytes::<VERIFYING_KEY_LEN>(v, &mut offset))
            .map_err(std::io::Error::other)?;
        let sk = SecretKey::from_slice(&read_bytes::<SECRET_KEY_LEN>(v, &mut offset))
            .map_err(std::io::Error::other)?;
        let nk_commit = read_bytes::<NULLIFIER_KEY_COMMITMENT_LEN>(v, &mut offset);
        Ok(Self { verifying_key: vk, secret_key: sk, nullifier_key_commitment: nk_commit })
    }
}

#[derive(Clone, Debug, Copy)]
pub struct PaymentAddress {
    pub verifying_key: VerifyingKey,
    pub public_key: PublicKey,
    pub nullifier_key_commitment: NullifierKeyCommitment,
}

impl Bech32 for PaymentAddress {
    const HRP: &str = "ztestsapling";

    fn to_vec(&self) -> std::io::Result<Vec<u8>> {
        let mut bytes = [0u8; VERIFYING_KEY_LEN + PUBLIC_KEY_LEN + NULLIFIER_KEY_COMMITMENT_LEN];
        let mut offset = 0;
        write_bytes(&mut bytes, &mut offset, &self.verifying_key.to_sec1_bytes());
        write_bytes(&mut bytes, &mut offset, &self.public_key.to_sec1_bytes());
        write_bytes(&mut bytes, &mut offset, &self.nullifier_key_commitment);
        Ok(bytes.to_vec())
    }

    fn from_slice(v: &[u8]) -> std::io::Result<Self> {
        if v.len() != VERIFYING_KEY_LEN + PUBLIC_KEY_LEN + NULLIFIER_KEY_COMMITMENT_LEN {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "unexpected length for PaymentAddress",
            ));
        }
        let mut offset = 0;
        let vk = VerifyingKey::from_sec1_bytes(&read_bytes::<VERIFYING_KEY_LEN>(v, &mut offset))
            .map_err(std::io::Error::other)?;
        let pk = PublicKey::from_sec1_bytes(&read_bytes::<PUBLIC_KEY_LEN>(v, &mut offset))
            .map_err(std::io::Error::other)?;
        let nk_commit = read_bytes::<NULLIFIER_KEY_COMMITMENT_LEN>(v, &mut offset);
        Ok(Self { verifying_key: vk, public_key: pk, nullifier_key_commitment: nk_commit })
    }
}

#[derive(Clone, Debug)]
pub struct ExtendedSpendingKey {
    pub signing_key: SigningKey,
    pub secret_key: SecretKey,
    pub nullifier_key: NullifierKey,
}

impl ExtendedSpendingKey {
    /// Generate an extended spending key
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let signing_key = SigningKey::random(rng);
        let secret_key = SecretKey::random(rng);
        let nullifier_key = NullifierKey::random(rng);
        Self { signing_key, secret_key, nullifier_key }
    }
    /// Convert to an extended full viewing key
    pub fn to_viewing_key(&self) -> ExtendedFullViewingKey {
        ExtendedFullViewingKey {
            verifying_key: *self.signing_key.verifying_key(),
            secret_key: self.secret_key.clone(),
            nullifier_key_commitment: self.nullifier_key.commit(),
        }
    }
}

impl Bech32 for ExtendedSpendingKey {
    const HRP: &str = "secret-extended-key-test";

    fn to_vec(&self) -> std::io::Result<Vec<u8>> {
        let mut bytes = [0u8; SIGNING_KEY_LEN + SECRET_KEY_LEN + NULLIFIER_KEY_LEN];
        let mut offset = 0;
        write_bytes(&mut bytes, &mut offset, &self.signing_key.to_bytes());
        write_bytes(&mut bytes, &mut offset, &self.secret_key.to_bytes());
        write_bytes(&mut bytes, &mut offset, &self.nullifier_key.0);
        Ok(bytes.to_vec())
    }

    fn from_slice(v: &[u8]) -> std::io::Result<Self> {
        if v.len() != SIGNING_KEY_LEN + SECRET_KEY_LEN + NULLIFIER_KEY_LEN {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "unexpected length for ExtendedSpendingKey",
            ));
        }
        let mut offset = 0;
        let vk = SigningKey::from_slice(&read_bytes::<SIGNING_KEY_LEN>(v, &mut offset))
            .map_err(std::io::Error::other)?;
        let sk = SecretKey::from_slice(&read_bytes::<SECRET_KEY_LEN>(v, &mut offset))
            .map_err(std::io::Error::other)?;
        let nk = read_bytes::<NULLIFIER_KEY_LEN>(v, &mut offset);
        Ok(Self { signing_key: vk, secret_key: sk, nullifier_key: NullifierKey(nk) })
    }
}

#[derive(Debug, Clone)]
pub struct Bech32Encoded<X>(pub X);

// --- String Conversion Traits ---

impl<X: Bech32> std::fmt::Display for Bech32Encoded<X> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_bech32m())
    }
}

impl<X: Bech32> FromStr for Bech32Encoded<X> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hrp, data) = bech32::decode(s).map_err(|e| e.to_string())?;

        // Validate HRP and Variant
        if hrp.as_str() != X::HRP {
            return Err(format!("Invalid HRP: expected {}, got {}", X::HRP, hrp));
        }

        // FullViewingKey is typically 96 bytes (ak, nk, ovk)
        let fvk = X::from_slice(&data[..])
            .map_err(|e| format!("Failed to parse FullViewingKey bytes: {}", e))?;

        Ok(Bech32Encoded(fvk))
    }
}

// --- Serde Implementation ---

impl<X: Bech32> Serialize for Bech32Encoded<X> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_bech32m())
    }
}

impl<'de, X: Bech32> Deserialize<'de> for Bech32Encoded<X> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <std::string::String as Deserialize>::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SerdeAdapter<X>(pub X);

// --- Serde Implementation ---

impl<X: ToString> Serialize for SerdeAdapter<X> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de, X: FromStr> Deserialize<'de> for SerdeAdapter<X>
where
    <X as FromStr>::Err: std::fmt::Display,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <std::string::String as Deserialize>::deserialize(deserializer)?;
        FromStr::from_str(&s)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// A Storage area for keys and addresses
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Store {
    /// Known viewing keys
    pub viewing_keys: BTreeMap<String, Bech32Encoded<ExtendedFullViewingKey>>,
    /// Known spending keys
    pub spending_keys: BTreeMap<String, Encrypted<ExtendedSpendingKey>>,
    /// Payment address book
    pub payment_addrs: BTreeMap<String, Bech32Encoded<PaymentAddress>>,
    /// Cryptographic keypairs
    pub signing_keys: BTreeMap<String, Encrypted<SigningKey>>,
    /// Known public keys
    pub verifying_keys: BTreeMap<String, B512>,
    /// Known addresses
    pub addresses: BTreeMap<String, Address>,
}

impl Store {
    // Load TOML file from path and Serde deserialize it
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        toml::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
    // Generate spending key, encrypt it, and store it under the alias,
    // also derive the viewing key and store it under the same alias
    pub fn generate_spending_key(
        &mut self,
        alias: String,
        rng: &mut impl CryptoRngCore,
        passphrase: String,
    ) -> Result<ExtendedSpendingKey, EncryptError> {
        let spending_key = ExtendedSpendingKey::random(rng);
        self.store_spending_key(alias, &spending_key, passphrase)?;
        Ok(spending_key)
    }
    // Encrypt the given spending key with the given password and store
    // it under the given alias replacing all assignments to the given alias
    pub fn store_spending_key(
        &mut self,
        alias: String,
        extsk: &ExtendedSpendingKey,
        passphrase: String,
    ) -> Result<(), EncryptError> {
        self.remove(&alias);
        // Encrypt and store this spending key
        let recipient = Recipient::new(SecretString::from(passphrase.clone()));
        let encrypted = age::encrypt(&recipient, &extsk.to_vec()?).map_err(std::io::Error::other)?;
        self.spending_keys
            .insert(alias.clone(), Encrypted(encrypted.to_vec(), PhantomData));
        // Store the full viewing key corresponding to this spending key
        let extfvk = extsk.to_viewing_key();
        self.viewing_keys.insert(alias.clone(), Bech32Encoded(extfvk.clone()));
        // Derive the payment address corresponding to this spending key
        let pa = extfvk.to_payment_address();
        self.payment_addrs.insert(alias, Bech32Encoded(pa));
        Ok(())
    }
    // Store the given viewing key under the given alias clearing all existing
    // assignments to that alias.
    pub fn store_viewing_key(&mut self, alias: String, key: ExtendedFullViewingKey) {
        self.remove(&alias);
        self.viewing_keys.insert(alias.clone(), Bech32Encoded(key.clone()));
        // Derive the payment address corresponding to this spending key
        let pa = key.to_payment_address();
        self.payment_addrs.insert(alias, Bech32Encoded(pa));
    }
    // Store the given Ethereum address under the given alias clearing all existing
    // assignments to that alias.
    pub fn store_address(&mut self, alias: String, addr: Address) {
        self.remove(&alias);
        self.addresses.insert(alias, addr);
    }
    // Store the given Ethereum address under the given alias clearing all existing
    // assignments to that alias.
    pub fn store_payment_address(&mut self, alias: String, addr: PaymentAddress) {
        self.remove(&alias);
        self.payment_addrs.insert(alias, Bech32Encoded(addr));
    }
    // Attempt to decrypt the key with given alias using the given passphrase
    pub fn decrypt_spending_key(
        &self,
        alias: String,
        passphrase: String,
    ) -> std::io::Result<ExtendedSpendingKey> {
        // Get the encrypted key from the store
        let enc_sk = self
            .spending_keys
            .get(&alias)
            .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "Alias not found"))?;
        let identity = Identity::new(SecretString::from(passphrase.clone()));
        // Decrypt the key using the passphrase
        let decrypted = age::decrypt(&identity, &enc_sk.0).map_err(std::io::Error::other)?;
        // Finally, construct a spending key object
        ExtendedSpendingKey::from_slice(&decrypted).map_err(|_| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                "Error decoding Sapling spending key",
            )
        })
    }
    // Attempt to decrypt the key with given alias using the given passphrase
    pub fn decrypt_signing_key(
        &self,
        alias: String,
        passphrase: String,
    ) -> std::io::Result<SigningKey> {
        // Get the encrypted key from the store
        let enc_sk = self
            .signing_keys
            .get(&alias)
            .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "Alias not found"))?;
        let identity = Identity::new(SecretString::from(passphrase.clone()));
        // Decrypt the key using the passphrase
        let decrypted = age::decrypt(&identity, &enc_sk.0).map_err(std::io::Error::other)?;
        // Convert the byte vector to a byte array
        let decrypted = TryInto::<[u8; 32]>::try_into(decrypted).map_err(|_| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                "Decrypted spending key has incorrect format",
            )
        })?;
        // Finally, construct a spending key object
        SigningKey::from_slice(&decrypted).map_err(std::io::Error::other)
    }
    // Merge the given store into self
    pub fn merge(&mut self, store: Self) {
        // First clear keys to avoid inconsistent state where the same alias
        // has unrelated keys
        store.viewing_keys.keys().for_each(|x| self.remove(x));
        store.spending_keys.keys().for_each(|x| self.remove(x));
        store.payment_addrs.keys().for_each(|x| self.remove(x));
        store.signing_keys.keys().for_each(|x| self.remove(x));
        store.verifying_keys.keys().for_each(|x| self.remove(x));
        store.addresses.keys().for_each(|x| self.remove(x));
        // Then do the extension
        self.viewing_keys.extend(store.viewing_keys);
        self.spending_keys.extend(store.spending_keys);
        self.payment_addrs.extend(store.payment_addrs);
        self.signing_keys.extend(store.signing_keys);
        self.verifying_keys.extend(store.verifying_keys);
        self.addresses.extend(store.addresses);
    }
    // Load the TOML store from the path, overwrite conflicting entries with self,
    // and also write the new store back to the file.
    pub fn synchronize(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        // Immediately lock file to avoid race conditions
        file.lock()?;
        // Read the store currently on the disk, give the default store if file empty
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let mut disk_store = if contents.is_empty() {
            Store::default()
        } else {
            toml::from_str(&contents)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        };
        // Merge `self` into `disk_store`, overwriting conflicts
        disk_store.merge(self.clone());
        // Update self to mirror the synchronized state
        *self = disk_store;
        // And finally overwrite the disk store
        let toml_string = toml::to_string(self)
            .map_err(std::io::Error::other)?
            .into_bytes();
        file.rewind()?;
        file.write_all(&toml_string)?;
        file.set_len(
            toml_string
                .len()
                .try_into()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::FileTooLarge, e))?,
        )?;
        Ok(())
    }
    // Does the given alias already exist on the store?
    pub fn exists(&self, alias: &str) -> bool {
        self.viewing_keys.contains_key(alias)
            || self.spending_keys.contains_key(alias)
            || self.payment_addrs.contains_key(alias)
            || self.signing_keys.contains_key(alias)
            || self.verifying_keys.contains_key(alias)
            || self.addresses.contains_key(alias)
    }
    // Remove the addresses and keys at the given alias
    pub fn remove(&mut self, alias: &str) {
        self.viewing_keys.remove(alias);
        self.spending_keys.remove(alias);
        self.payment_addrs.remove(alias);
        self.signing_keys.remove(alias);
        self.verifying_keys.remove(alias);
        self.addresses.remove(alias);
    }
    // Generate secret key, encrypt it, and store it under the alias,
    // also derive the public key and address and store them under the same alias
    pub fn generate_signing_key(
        &mut self,
        alias: String,
        rng: &mut impl CryptoRngCore,
        passphrase: String,
    ) -> Result<SigningKey, EncryptError> {
        let sk = SigningKey::random(rng);
        self.store_signing_key(alias, sk.clone(), passphrase)?;
        Ok(sk)
    }
    // Encrypt the given signing key with the given password and store
    // it under the given alias replacing all assignments to the given alias
    pub fn store_signing_key(
        &mut self,
        alias: String,
        key: SigningKey,
        passphrase: String,
    ) -> Result<(), EncryptError> {
        self.remove(&alias);
        // Encrypt and store this secret key
        let recipient = Recipient::new(SecretString::from(passphrase.clone()));
        let encrypted = age::encrypt(&recipient, &key.to_bytes())?;
        self.signing_keys
            .insert(alias.clone(), Encrypted(encrypted.to_vec(), PhantomData));
        let pks = PrivateKeySigner::from_signing_key(key);
        self.verifying_keys.insert(alias.clone(), pks.public_key());
        self.addresses.insert(alias, pks.address());
        Ok(())
    }
    // Try to interpret the argument as a literal address and, failing that,
    // attempt to interpret it as an alias of an address in the store.
    pub fn evaluate_address(&self, expr: &String) -> std::io::Result<Address> {
        if let Ok(value) = Address::parse_checksummed(expr, None) {
            Ok(value)
        } else if let Some(value) = self.addresses.get(expr) {
            Ok(*value)
        } else {
            Err(std::io::Error::other(format!(
                "Unable to find alias: {}",
                expr
            )))
        }
    }
    // Try to interpret the argument as a literal viewing key and, failing that,
    // attempt to interpret it as an alias of a viewing key in the store.
    pub fn evaluate_viewing_key(&self, expr: &String) -> std::io::Result<ExtendedFullViewingKey> {
        if let Ok(value) = expr.parse::<Bech32Encoded<ExtendedFullViewingKey>>() {
            Ok(value.0)
        } else if let Some(value) = self.viewing_keys.get(expr) {
            Ok(value.0.clone())
        } else {
            Err(std::io::Error::other(format!(
                "Unable to find alias: {}",
                expr
            )))
        }
    }
    // Try to interpret the argument as a literal payment address and, failing that,
    // attempt to interpret it as an alias of a payment address in the store.
    pub fn evaluate_payment_address(&self, expr: &String) -> std::io::Result<PaymentAddress> {
        if let Ok(value) = expr.parse::<Bech32Encoded<PaymentAddress>>() {
            Ok(value.0)
        } else if let Some(value) = self.payment_addrs.get(expr) {
            Ok(value.0)
        } else {
            Err(std::io::Error::other(format!(
                "Unable to find alias: {}",
                expr
            )))
        }
    }
}
