use rsa::BigUint;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::resource::RecordType;
use crate::resource_record_set::ResourceRecordSet;

/// The NSEC resource record lists two separate things: the next owner
/// name (in the canonical ordering of the zone) that contains
/// authoritative data or a delegation point NS RRset, and the set of RR
/// types present at the NSEC RR's owner name [RFC3845].  The complete
/// set of NSEC RRs in a zone indicates which authoritative RRsets exist
/// in a zone and also form a chain of authoritative owner names in the
/// zone.  This information is used to provide authenticated denial of
/// existence for DNS data, as described in [RFC4035].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NSEC {
    next_domain_name: FQDN,
    types: Vec<RecordType>,
}

impl NSEC {
    pub fn new(next_domain_name: FQDN) -> Self {
        Self {
            next_domain_name,
            types: Vec::new(),
        }
    }

    pub fn with_types(next_domain_name: FQDN, mut types: Vec<RecordType>) -> Self {
        // Make sure the types bitmap is always sorted
        types.sort_by(|a, b| (*a as u16).cmp(&(*b as u16)));
        Self {
            next_domain_name,
            types,
        }
    }

    pub fn next_domain_name(&self) -> &FQDN {
        &self.next_domain_name
    }

    pub fn types(&self) -> &[RecordType] {
        &self.types
    }

    /// Inserts a new record type into the type bit map
    /// The record type is inserted at the correct place to ensure the bitmap stays sorted
    pub fn add_rtype(&mut self, rtype: RecordType) {
        for (idx, stored_type) in self.types.iter().enumerate() {
            if *stored_type as u16 > rtype as u16 {
                self.types.insert(idx, rtype);
                return;
            } else if rtype == *stored_type {
                return;
            }
        }
        self.types.push(rtype);
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for NSEC {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let next_domain_name = buffer.extract_fqdn()?;

        // Extract the mentioned record types from the binary data representation
        let mut types = Vec::new();
        while buffer.remaining() > 0 {
            let window_num = buffer.extract_u8()? as u16;
            let window_len = buffer.extract_u8()? as u16;

            // By extracting the RRTypes from the bitmap it is "guaranteed" that the resulting vec
            // self.types is sorted
            let bitmap = buffer.extract_bytes(window_len as usize)?;
            for (index, octet) in bitmap.iter().enumerate() {
                for i in 0..8 {
                    if (octet << i) & 0x80 > 0 {
                        let bit_position = (256 * window_num) + (8 * index as u16) + i;
                        types.push(RecordType::try_from(bit_position)?);
                    }
                }
            }
        }

        Ok(Self {
            next_domain_name,
            types,
        })
    }
}

impl ByteConvertible for NSEC {
    #[inline(always)]
    fn byte_size(&self) -> usize {
        let mut byte_size = self.next_domain_name.byte_size();

        let mut block_num: u16 = 0;
        for i in 0..=self.types.len() {
            if i == self.types.len() || self.types[i] as u16 - (block_num * 32) > 255 {
                // Update length with next finished block
                byte_size += 2; // window number and block length
                let num_octets = ((self.types[i - 1] as u16 / 8) - (32 * block_num)) as usize;
                byte_size += num_octets + 1; // Octet index of last entry equals the block length

                block_num += 1;
            }
        }

        return byte_size;
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.next_domain_name.to_bytes());

        // Encode windows {u8 windowblock, u8 bitmaplength, 0-32u8 bitmap}
        // Each Block is 0-255 upper octet of types, length if 0-32
        let mut block_num = 0;
        let mut block_len: u8 = 0;
        let mut block_data = [0_u8; 32];
        for i in 0..=self.types.len() {
            if i == self.types.len() || self.types[i] as u16 - (block_num * 32) > 255 {
                // Finish last block by pushing it into the output buffer
                buffer.push(block_num as u8);
                buffer.push(block_len + 1 as u8);
                buffer.extend_from_slice(&block_data[0..=block_len as usize]);

                // Start new block
                block_num += 1;
                block_len = 0;
                block_data.fill(0);
            }

            if i < self.types.len() {
                // Continue in previous block
                block_len = ((self.types[i] as u16 / 8) - (32 * block_num)) as u8;
                let bit_in_octet = self.types[i] as u16 % 8;

                block_data[block_len as usize] |= 128 >> bit_in_octet as u8;
            }
        }

        buffer
    }
}

impl CompressedByteConvertible for NSEC {
    fn to_bytes_compressed(
        &self,
        names: &mut std::collections::HashMap<u64, usize>,
        offset: usize,
    ) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.next_domain_name.to_bytes_compressed(names, offset));

        // Encode windows {u8 windowblock, u8 bitmaplength, 0-32u8 bitmap}
        // Each Block is 0-255 upper octet of types, length if 0-32
        let mut block_num = 0;
        let mut block_len: u8 = 0;
        let mut block_data = [0_u8; 32];
        for i in 0..=self.types.len() {
            if i == self.types.len() || self.types[i] as u16 - (block_num * 32) > 255 {
                // Finish last block by pushing it into the output buffer
                buffer.push(block_num as u8);
                buffer.push(block_len + 1 as u8);
                buffer.extend_from_slice(&block_data[0..=block_len as usize]);

                // Start new block
                block_num += 1;
                block_len = 0;
                block_data.fill(0);
            }

            if i < self.types.len() {
                // Continue in previous block
                block_len = ((self.types[i] as u16 / 8) - (32 * block_num)) as u8;
                let bit_in_octet = self.types[i] as u16 % 8;

                block_data[block_len as usize] |= 128 >> bit_in_octet as u8;
            }
        }

        buffer
    }
}

/// DNSSEC uses public key cryptography to sign and authenticate DNS
/// resource record sets (RRsets).  The public keys are stored in DNSKEY
/// resource records and are used in the DNSSEC authentication process
/// described in [RFC4035]: A zone signs its authoritative RRsets by
/// using a private key and stores the corresponding public key in a
/// DNSKEY RR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DNSKEY {
    zone_key: bool,
    secure_entry_point: bool,
    protocol: u8,
    algorithm: Algorithm,
    public_key: Vec<u8>,
}

impl DNSKEY {
    pub fn new(algorithm: Algorithm, public_key: Vec<u8>) -> Self {
        Self {
            zone_key: false,
            secure_entry_point: false,
            protocol: 3,
            algorithm,
            public_key,
        }
    }

    pub fn zone_key(&self) -> bool {
        self.zone_key
    }

    pub fn set_zone_key(&mut self, zone_key: bool) {
        self.zone_key = zone_key;
    }

    pub fn secure_entry_point(&self) -> bool {
        self.secure_entry_point
    }

    pub fn set_secure_entry_point(&mut self, secure_entry_point: bool) {
        self.secure_entry_point = secure_entry_point;
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Protocol validation check
    pub fn valid_protocol(&self) -> bool {
        // Only if protocol is equal to 3 it is valid
        self.protocol == 3
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The base64-encoded public key.
    pub fn base64_public_key(&self) -> String {
        use base64::{engine::general_purpose, Engine as _};
        general_purpose::STANDARD.encode(&self.public_key)
    }

    /// Computes the key tag field for the RRSIG and DS records to provide a mechanism for selecting a
    /// public key efficiently
    /// First octet of the key tag is the most significant 8 bits of the return value
    /// Second octet of the key tag is the least significant 8 bits of the return value
    fn compute_key_tag(&self) -> u16 {
        let mut key_tag = self
            .to_bytes()
            .iter()
            .enumerate()
            .fold(0_u32, |ac, (i, b)| {
                ac + if i & 1 != 0 {
                    *b as u32
                } else {
                    (*b as u32) << 8
                }
            });
        key_tag += (key_tag >> 16) & 0xFFFF;
        return (key_tag & 0xFFFF) as u16;
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for DNSKEY {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let flags = buffer.extract_u16()?;
        let protocol = buffer.extract_u8()?;
        let algorithm: Algorithm = buffer.extract_u8()?.try_into()?;
        let public_key = buffer.extract_bytes(buffer.remaining())?.to_vec();

        Ok(Self {
            zone_key: (flags & 0b00000001_00000000) != 0,
            secure_entry_point: (flags & 0b00000000_00000001) != 0,
            protocol,
            algorithm,
            public_key,
        })
    }
}

impl ByteConvertible for DNSKEY {
    #[inline(always)]
    fn byte_size(&self) -> usize {
        4 + self.public_key.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buff = Vec::with_capacity(4 + self.public_key.len());
        let combined_flags = ((self.zone_key as u16) << 8) | self.secure_entry_point as u16;
        buff.extend_from_slice(&u16::to_be_bytes(combined_flags));
        buff.push(self.protocol);
        buff.push((self.algorithm).into());
        buff.extend_from_slice(&self.public_key);
        buff
    }
}

/// The DS Resource Record refers to a DNSKEY RR and is used in the DNS
/// DNSKEY authentication process.  A DS RR refers to a DNSKEY RR by
/// storing the key tag, algorithm number, and a digest of the DNSKEY RR.
/// Note that while the digest should be sufficient to identify the
/// public key, storing the key tag and key algorithm helps make the
/// identification process more efficient.  By authenticating the DS
/// record, a resolver can authenticate the DNSKEY RR to which the DS
/// record points.  The key authentication process is described in
/// [RFC4035].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DS {
    key_tag: u16,
    algorithm: Algorithm,
    digest_type: DigestType,
    digest: Vec<u8>,
}

impl DS {
    pub fn new(
        key_tag: u16,
        algorithm: Algorithm,
        digest_type: DigestType,
        digest: Vec<u8>,
    ) -> Self {
        Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        }
    }

    pub fn try_from_dnskey(
        owner_name: &FQDN,
        dnskey: &DNSKEY,
        digest_type: DigestType,
    ) -> Result<Self, DnsError> {
        let mut digest_data = Vec::with_capacity(owner_name.byte_size() + dnskey.byte_size());
        digest_data.extend_from_slice(&owner_name.to_bytes());
        digest_data.extend_from_slice(&dnskey.to_bytes());

        Ok(Self {
            key_tag: dnskey.compute_key_tag(),
            algorithm: dnskey.algorithm,
            digest_type,
            digest: digest_type.hash_data(&digest_data)?,
        })
    }

    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Returns the hexadecimal representation of the digest
    pub fn hex_digest(&self) -> String {
        self.digest
            .iter()
            .map(|byte| format!("{:02X}", byte))
            .collect()
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn digest_type(&self) -> DigestType {
        self.digest_type
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for DS {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            key_tag: buffer.extract_u16()?,
            algorithm: buffer.extract_u8()?.try_into()?,
            digest_type: buffer.extract_u8()?.try_into()?,
            digest: buffer.extract_bytes(buffer.remaining())?.to_vec(),
        })
    }
}

impl ByteConvertible for DS {
    #[inline(always)]
    fn byte_size(&self) -> usize {
        4 + self.digest.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(4 + self.digest.len());
        buffer.extend_from_slice(&u16::to_be_bytes(self.key_tag));
        buffer.push(self.algorithm.into());
        buffer.push(self.digest_type.into());
        buffer.extend_from_slice(&self.digest);
        buffer
    }
}

/// An RRSIG record contains the signature for an RRset with a particular
/// name, class, and type.  The RRSIG RR specifies a validity interval
/// for the signature and uses the Algorithm, the Signer's Name, and the
/// Key Tag to identify the DNSKEY RR containing the public key that a
/// validator can use to verify the signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RRSIG {
    type_covered: RecordType,
    algorithm: Algorithm,
    labels: u8,
    original_ttl: u32,
    sig_expiration: u32,
    sig_inception: u32,
    key_tag: u16,
    signers_name: FQDN,
    signature: Vec<u8>,
}

impl RRSIG {
    pub fn new(
        type_covered: RecordType,
        algorithm: Algorithm,
        labels: u8,
        original_ttl: u32,
        sig_expiration: u32,
        sig_inception: u32,
        key_tag: u16,
        signers_name: FQDN,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            sig_expiration,
            sig_inception,
            key_tag,
            signers_name,
            signature,
        }
    }

    pub fn from_dnskey(
        dnskey: &DNSKEY,
        rr_set: &ResourceRecordSet,
        inception: &SystemTime,
        expiration: &SystemTime,
        private_key: &[u8],
    ) -> Result<Self, DnsError> {
        let expiration = expiration
            .duration_since(UNIX_EPOCH)
            .map_err(|err| DnsError::InvalidDnsSecSignatureTimespan(err))?
            .as_millis() as u32;
        let inception = inception
            .duration_since(UNIX_EPOCH)
            .map_err(|err| DnsError::InvalidDnsSecSignatureTimespan(err))?
            .as_millis() as u32;

        let mut rrsig = Self {
            type_covered: rr_set.set_type(),
            algorithm: dnskey.algorithm,
            labels: rr_set.name().label_count(),
            original_ttl: rr_set.ttl(),
            sig_expiration: expiration,
            sig_inception: inception,
            key_tag: dnskey.compute_key_tag(),
            signers_name: rr_set.name().clone(),
            signature: Vec::default(),
        };

        rrsig.calculate_signature(rr_set, private_key)?;

        return Ok(rrsig);
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The base64-encoded public key.
    pub fn base64_signature(&self) -> String {
        use base64::{engine::general_purpose, Engine as _};
        general_purpose::STANDARD.encode(&self.signature)
    }

    pub fn verify(&self, dnskey: &DNSKEY, rr_set: &ResourceRecordSet) -> Result<bool, DnsError> {
        if self.algorithm != dnskey.algorithm {
            // Signature can not be created by the key if the algorithms do not match
            return Err(DnsError::DnsSecVerificationError(
                "Non matching algorithms".into(),
            ));
        }

        // TODO Verify timeframe of the rrsig record

        // Create the input data that is compared with the signature of self
        // The data includes self but without the calculated signature
        let mut sig = Vec::with_capacity(self.byte_size());
        sig.extend_from_slice(&u16::to_be_bytes(self.type_covered.into()));
        sig.push(self.algorithm.into());
        sig.push(self.labels);
        sig.extend(u32::to_be_bytes(self.original_ttl));
        sig.extend(u32::to_be_bytes(self.sig_expiration));
        sig.extend(u32::to_be_bytes(self.sig_inception));
        sig.extend(u16::to_be_bytes(self.key_tag));
        sig.extend(self.signers_name.to_bytes());
        sig.extend(rr_set.to_bytes());

        // For some algorithms the hash is calculated independently of the verification algorithm
        let sig = match self.algorithm {
            Algorithm::RSA_MD5 => {
                use md5::{Digest, Md5};
                let mut hasher = Md5::new();
                hasher.update(sig);
                hasher.finalize().to_vec()
            }
            Algorithm::RSA_SHA1 | Algorithm::DSA_SHA1 => {
                use sha1::{Digest, Sha1};
                let mut hasher = Sha1::new();
                hasher.update(sig);
                hasher.finalize().to_vec()
            }
            Algorithm::RSA_SHA256 => {
                use ring::digest;
                digest::digest(&digest::SHA256, &sig).as_ref().to_vec()
            }
            Algorithm::RSA_SHA512 => {
                use ring::digest;
                digest::digest(&digest::SHA512, &sig).as_ref().to_vec()
            }
            _ => sig,
        };

        let mut public_key_data = DnsBuffer::from(dnskey.public_key());
        match self.algorithm {
            Algorithm::RSA_MD5
            | Algorithm::RSA_SHA1
            | Algorithm::RSA_SHA256
            | Algorithm::RSA_SHA512 => {
                // Key data field:
                // exponent length   1 or 3 octets (see text)
                // exponent          as specified by length field
                // modulus           remaining space

                let first_byte = public_key_data.extract_u8()?;
                let exp_len = if first_byte == 0 {
                    public_key_data.extract_u16()?
                } else {
                    first_byte as u16
                };

                let exponent =
                    BigUint::from_bytes_be(public_key_data.extract_bytes(exp_len as usize)?);
                let modulus = BigUint::from_bytes_be(
                    public_key_data.extract_bytes(public_key_data.remaining())?,
                );

                let verifier = rsa::RsaPublicKey::new(modulus, exponent)
                    .map_err(|err| DnsError::DnsSecVerificationError(err.to_string()))?;

                Ok(verifier
                    .verify(
                        rsa::pkcs1v15::Pkcs1v15Sign::new_unprefixed(),
                        &sig,
                        &self.signature,
                    )
                    .is_ok())
            }
            Algorithm::DSA_SHA1 => {
                use dsa::signature::Verifier;

                // Key data field:
                // T         1  octet
                // Q        20  octets
                // P        64 + T*8  octets
                // G        64 + T*8  octets
                // Y        64 + T*8  octets
                let t = public_key_data.extract_u8()? as usize;
                let q = BigUint::from_bytes_be(public_key_data.extract_bytes(20)?);
                let p = BigUint::from_bytes_be(public_key_data.extract_bytes(64 + t * 8)?);
                let g = BigUint::from_bytes_be(public_key_data.extract_bytes(64 + t * 8)?);
                let y = BigUint::from_bytes_be(public_key_data.extract_bytes(64 + t * 8)?);

                let verifier = dsa::VerifyingKey::from_components(
                    dsa::Components::from_components(p, q, g)
                        .map_err(|err| DnsError::DnsSecVerificationError(err.to_string()))?,
                    y,
                )
                .map_err(|err| DnsError::DnsSecVerificationError(err.to_string()))?;

                let signature = dsa::Signature::try_from(self.signature.as_slice())
                    .map_err(|err| DnsError::DnsSecVerificationError(err.to_string()))?;

                Ok(verifier.verify(&sig, &signature).is_ok())
            }
            Algorithm::ECDSA_P256 => {
                // Key data field:
                // 64 bytes (x | y)
                let verifier = ring::signature::UnparsedPublicKey::new(
                    &ring::signature::ECDSA_P256_SHA256_FIXED,
                    public_key_data.extract_bytes(public_key_data.remaining())?,
                );

                Ok(verifier.verify(&sig, &self.signature).is_ok())
            }
            Algorithm::ECDSA_P384 => {
                // Key data field:
                // 97 bytes (x | y)
                let verifier = ring::signature::UnparsedPublicKey::new(
                    &ring::signature::ECDSA_P384_SHA384_FIXED,
                    public_key_data.extract_bytes(public_key_data.remaining())?,
                );

                Ok(verifier.verify(&sig, &self.signature).is_ok())
            }
            Algorithm::ED25519 => {
                // Key data field:
                // 32 bytes
                let verifier = ring::signature::UnparsedPublicKey::new(
                    &ring::signature::ED25519,
                    public_key_data.extract_bytes(public_key_data.remaining())?,
                );

                Ok(verifier.verify(&sig, &self.signature).is_ok())
            }
            Algorithm::ED448 => {
                // Key data field:
                // 57 bytes
                let verifier = crrl::ed448::PublicKey::decode(
                    public_key_data.extract_bytes(public_key_data.remaining())?,
                )
                .ok_or(DnsError::DnsSecVerificationError("Invalid key data".into()))?;

                Ok(verifier.verify_raw(&self.signature, &sig))
            }
            _ => Ok(false),
        }
    }

    fn calculate_signature(
        &mut self,
        rr_set: &ResourceRecordSet,
        private_key: &[u8],
    ) -> Result<(), DnsError> {
        let mut sig = self.to_bytes();
        sig.extend(rr_set.to_bytes());

        self.signature = self.algorithm.sign_data(&sig, private_key)?;

        Ok(())
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for RRSIG {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            type_covered: buffer.extract_u16()?.try_into()?,
            algorithm: buffer.extract_u8()?.try_into()?,
            labels: buffer.extract_u8()?,
            original_ttl: buffer.extract_u32()?,
            sig_expiration: buffer.extract_u32()?,
            sig_inception: buffer.extract_u32()?,
            key_tag: buffer.extract_u16()?,
            signers_name: buffer.extract_fqdn()?,
            signature: buffer.extract_bytes(buffer.remaining())?.to_vec(),
        })
    }
}

impl ByteConvertible for RRSIG {
    #[inline(always)]
    fn byte_size(&self) -> usize {
        17 + self.signers_name.len() + self.signature.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.byte_size());
        buffer.extend_from_slice(&u16::to_be_bytes(self.type_covered.into()));
        buffer.push(self.algorithm.into());
        buffer.push(self.labels);
        buffer.extend_from_slice(&u32::to_be_bytes(self.original_ttl));
        buffer.extend_from_slice(&u32::to_be_bytes(self.sig_expiration));
        buffer.extend_from_slice(&u32::to_be_bytes(self.sig_inception));
        buffer.extend_from_slice(&u16::to_be_bytes(self.key_tag));
        buffer.extend_from_slice(&self.signers_name.to_bytes());
        buffer.extend_from_slice(&self.signature);
        buffer
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Algorithm {
    RSA_MD5,
    DSA_SHA1,
    RSA_SHA1,
    //
    RSA_SHA256,
    //
    RSA_SHA512,
    //
    // GOST = 12, // Currently unsupported
    ECDSA_P256,
    ECDSA_P384,
    ED25519,
    ED448,
    //
    Indirect,
    PrivateDns,
    PrivateOid,
}

impl Algorithm {
    pub fn len(&self) -> Option<usize> {
        match self {
            Self::RSA_MD5 => Some(16),                    // 128 bits
            Self::DSA_SHA1 | Self::RSA_SHA1 => Some(20),  // 160 bits
            Self::RSA_SHA256 | Self::ED25519 => Some(32), // 256 bits
            Self::RSA_SHA512 | Self::ED448 => Some(64),   // 512 bites
            _ => None,
        }
    }

    pub fn sign_data(&self, data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, DnsError> {
        let rng = ring::rand::SystemRandom::new();

        match self {
            Self::RSA_MD5 => {
                use md5::{Digest, Md5};
                use rsa::pkcs8::DecodePrivateKey;

                let mut hasher = Md5::new();
                hasher.update(data);
                let digest = hasher.finalize();

                let private_key = rsa::RsaPrivateKey::from_pkcs8_der(private_key)
                    .map_err(|err| DnsError::DnsSecSigningError(err.to_string()))?;

                let signature = private_key
                    .sign(
                        rsa::pkcs1v15::Pkcs1v15Sign::new_unprefixed(),
                        digest.as_ref(),
                    )
                    .map_err(|err| DnsError::DnsSecSigningError(err.to_string()))?;

                Ok(signature)
            }
            Self::DSA_SHA1 => {
                use dsa::{pkcs8::DecodePrivateKey, SigningKey};
                use sha1::{Digest, Sha1};
                use signature::DigestSigner;

                let mut hasher = Sha1::new();
                hasher.update(data);

                let signing_key = SigningKey::from_pkcs8_der(private_key)
                    .map_err(|err| DnsError::DnsSecSigningError(err.to_string()))?;
                let signature = signing_key.sign_digest(hasher);

                let mut sign_data = signature.r().to_bytes_be();
                sign_data.extend_from_slice(&signature.s().to_bytes_be());

                Ok(sign_data)
            }
            Self::RSA_SHA1 => {
                use rsa::pkcs8::DecodePrivateKey;
                use sha1::{Digest, Sha1};

                let mut hasher = Sha1::new();
                hasher.update(data);
                let digest = hasher.finalize();

                let private_key = rsa::RsaPrivateKey::from_pkcs8_der(private_key)
                    .map_err(|err| DnsError::DnsSecSigningError(err.to_string()))?;

                let signature = private_key
                    .sign(
                        rsa::pkcs1v15::Pkcs1v15Sign::new_unprefixed(),
                        digest.as_ref(),
                    )
                    .map_err(|err| DnsError::DnsSecSigningError(err.to_string()))?;

                Ok(signature)
            }
            Self::RSA_SHA256 => {
                let rsa_key_pair = ring::rsa::KeyPair::from_pkcs8(private_key)
                    .map_err(|err| DnsError::DnsSecSigningError(err.to_string()))?;
                let mut signature = vec![0; rsa_key_pair.public().modulus_len()];
                let _ = rsa_key_pair
                    .sign(
                        &ring::signature::RSA_PKCS1_SHA256,
                        &rng,
                        data,
                        &mut signature,
                    )
                    .map_err(|_| todo!());
                Ok(signature)
            }
            Self::RSA_SHA512 => {
                let rsa_key_pair = ring::rsa::KeyPair::from_pkcs8(private_key)
                    .map_err(|err| DnsError::DnsSecSigningError(err.to_string()))?;
                let mut signature = vec![0; rsa_key_pair.public().modulus_len()];
                let _ = rsa_key_pair
                    .sign(
                        &ring::signature::RSA_PKCS1_SHA512,
                        &rng,
                        data,
                        &mut signature,
                    )
                    .map_err(|_| todo!());
                Ok(signature)
            }
            Self::ECDSA_P256 => {
                let ecdsa_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
                    &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    private_key,
                    &rng,
                )
                .map_err(|err| DnsError::DnsSecSigningError(err.to_string()))?;
                let signature = ecdsa_key_pair
                    .sign(&rng, data)
                    .map_err(|err| DnsError::DnsSecSigningError(err.to_string()))?;
                Ok(signature.as_ref().to_vec())
            }
            Self::ECDSA_P384 => {
                let ecdsa_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
                    &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                    private_key,
                    &rng,
                )
                .map_err(|err| DnsError::DnsSecSigningError(err.to_string()))?;
                let signature = ecdsa_key_pair
                    .sign(&rng, data)
                    .map_err(|err| DnsError::DnsSecSigningError(err.to_string()))?;
                Ok(signature.as_ref().to_vec())
            }
            Self::ED25519 => {
                let ed25519_key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(private_key)
                    .map_err(|err| DnsError::DnsSecSigningError(err.to_string()))?;
                let signature = ed25519_key_pair.sign(data);
                Ok(signature.as_ref().to_vec())
            }
            Self::ED448 => {
                let ed448_key = crrl::ed448::PrivateKey::decode(private_key).ok_or(
                    DnsError::DnsSecSigningError("Failed to create key from input".into()),
                )?;

                let signature = ed448_key.sign_raw(data);
                Ok(signature.to_vec())
            }
            Self::Indirect => Err(DnsError::InvalidDnsSecAlgorithm(*self as u8)),
            Self::PrivateDns => Err(DnsError::InvalidDnsSecAlgorithm(*self as u8)),
            Self::PrivateOid => Err(DnsError::InvalidDnsSecAlgorithm(*self as u8)),
        }
    }
}

impl TryFrom<u8> for Algorithm {
    type Error = DnsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::RSA_MD5),
            3 => Ok(Self::DSA_SHA1),
            5 => Ok(Self::RSA_SHA1),
            8 => Ok(Self::RSA_SHA256),
            10 => Ok(Self::RSA_SHA512),
            13 => Ok(Self::ECDSA_P256),
            14 => Ok(Self::ECDSA_P384),
            15 => Ok(Self::ED25519),
            16 => Ok(Self::ED448),
            252 => Ok(Self::Indirect),
            253 => Ok(Self::PrivateDns),
            254 => Ok(Self::PrivateOid),
            _ => Err(DnsError::InvalidDnsSecAlgorithm(value)),
        }
    }
}

impl From<Algorithm> for u8 {
    fn from(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::RSA_MD5 => 1,
            Algorithm::DSA_SHA1 => 3,
            Algorithm::RSA_SHA1 => 5,
            Algorithm::RSA_SHA256 => 8,
            Algorithm::RSA_SHA512 => 10,
            Algorithm::ECDSA_P256 => 13,
            Algorithm::ECDSA_P384 => 14,
            Algorithm::ED25519 => 15,
            Algorithm::ED448 => 16,
            Algorithm::Indirect => 252,
            Algorithm::PrivateDns => 253,
            Algorithm::PrivateOid => 254,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DigestType {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}

impl DigestType {
    pub fn hash_data(&self, data: &[u8]) -> Result<Vec<u8>, DnsError> {
        // digest = digest_algorithm(dnskey owner name + dnskey.flags + dnskey.protocol +
        // dnskey.algorithm + dnskey.pubblic_key);
        let digest_algorithm = match self {
            DigestType::SHA1 => &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
            DigestType::SHA256 => &ring::digest::SHA256,
            DigestType::SHA384 => &ring::digest::SHA384,
            DigestType::SHA512 => &ring::digest::SHA512,
        };
        Ok(ring::digest::digest(digest_algorithm, data)
            .as_ref()
            .to_vec())
    }
}

impl TryFrom<u8> for DigestType {
    type Error = DnsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::SHA1),
            2 => Ok(Self::SHA256),
            4 => Ok(Self::SHA384),
            5 => Ok(Self::SHA512),
            _ => Err(DnsError::InvalidDnsSecDigestType(value)),
        }
    }
}

impl From<DigestType> for u8 {
    fn from(digest_type: DigestType) -> Self {
        match digest_type {
            DigestType::SHA1 => 1,
            DigestType::SHA256 => 2,
            DigestType::SHA384 => 4,
            DigestType::SHA512 => 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn parse_nsec() {
        use RecordType::*;

        {
            let binary = b"\x00\x00\x06\x40\x00\x80\x08\x00\x03";
            let mut buffer = crate::buffer::DnsBuffer::from(&binary[..]);

            let nsec = super::NSEC::try_from(&mut buffer);
            assert!(nsec.is_ok());

            let nsec = nsec.unwrap();
            assert_eq!(nsec.types, vec![A, TXT, AAAA, RRSIG, NSEC]);
        }
        {
            let binary = b"\x00\x00\x07\x62\x00\x80\x08\x00\x03\x80";
            let mut buffer = crate::buffer::DnsBuffer::from(&binary[..]);

            let nsec = super::NSEC::try_from(&mut buffer);
            assert!(nsec.is_ok());

            let mut nsec = nsec.unwrap();
            assert_eq!(nsec.types, vec![A, NS, SOA, TXT, AAAA, RRSIG, NSEC, DNSKEY]);

            nsec.add_rtype(PTR);
            assert_eq!(
                nsec.types,
                vec![A, NS, SOA, PTR, TXT, AAAA, RRSIG, NSEC, DNSKEY]
            );

            nsec.add_rtype(URI);
            assert_eq!(
                nsec.types,
                vec![A, NS, SOA, PTR, TXT, AAAA, RRSIG, NSEC, DNSKEY, URI]
            )
        }
    }

    #[test]
    fn build_nsec() {
        use ByteConvertible;
        use RecordType::*;

        let nsec = super::NSEC {
            next_domain_name: crate::FQDN::from("."),
            types: vec![A, MX, RRSIG, NSEC, URI, CAA],
        };

        assert_eq!(nsec.byte_size(), 12);
        assert_eq!(
            nsec.to_bytes(),
            b"\x00\x00\x06\x40\x01\x00\x00\x00\x03\x01\x01\xC0"
        );
    }

    #[test]
    fn build_ds() {
        use base64::Engine;

        let pubkey_bytes = base64::engine::general_purpose::STANDARD
            .decode("AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz")
            .expect("Failed to base64-decode the public key");
        let mut dnskey = DNSKEY::new(rdata::dnssec::Algorithm::RSA_SHA256, pubkey_bytes);
        dnskey.set_zone_key(true);

        let ds = DS::try_from_dnskey(
            &FQDN::new("miek.nl."),
            &dnskey,
            rdata::dnssec::DigestType::SHA1,
        );
        assert!(ds.is_ok());

        let ds = ds.unwrap();
        assert_eq!(ds.key_tag, 12051);
        assert_eq!(ds.hex_digest(), "B5121BDB5B8D86D0CC5FFAFBAAABE26C3E20BAC1");
    }

    #[test]
    fn build_rrsig_rsa_sha1() {
        use base64::Engine;
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::traits::PublicKeyParts;
        use std::time::{Duration, UNIX_EPOCH};

        let base64_engine = base64::engine::general_purpose::STANDARD;

        // Create record for the RRset
        let set_name = FQDN::from("miek.nl");
        let soa = RecordData::SOA {
            mname: FQDN::from("open.nlnetlabs.nl"),
            rname: FQDN::from("miekg.atoom.net"),
            serial: 1293945905,
            refresh: 14400,
            retry: 3600,
            expire: 604800,
            minimum: 86400,
        };
        let set = ResourceRecordSet::new(
            &set_name,
            RecordType::SOA,
            RecordClass::IN,
            14400,
            vec![&soa],
        );

        let mut dnskey = DNSKEY::new(
            rdata::dnssec::Algorithm::RSA_SHA1,
            base64_engine.decode("AwEAAb+8lGNCxJgLS8rYVer6EnHVuIkQDghdjdtewDzU3G5R7PbMbKVRvH2Ma7pQyYceoaqWZQirSj72euPWfPxQnMy9ucCylA+FuH9cSjIcPf4PqJfdupHk9X6EBYjxrCLY4p1/yBwgyBIRJtZtAqM3ceAH2WovEJD6rTtOuHo5AluJ")
            .unwrap()
        );
        dnskey.set_zone_key(true);

        assert_eq!(dnskey.base64_public_key(), "AwEAAb+8lGNCxJgLS8rYVer6EnHVuIkQDghdjdtewDzU3G5R7PbMbKVRvH2Ma7pQyYceoaqWZQirSj72euPWfPxQnMy9ucCylA+FuH9cSjIcPf4PqJfdupHk9X6EBYjxrCLY4p1/yBwgyBIRJtZtAqM3ceAH2WovEJD6rTtOuHo5AluJ");

        let private_key = rsa::RsaPrivateKey::from_components(
            rsa::BigUint::from_bytes_be(&base64_engine.decode("v7yUY0LEmAtLythV6voScdW4iRAOCF2N217APNTcblHs9sxspVG8fYxrulDJhx6hqpZlCKtKPvZ649Z8/FCczL25wLKUD4W4f1xKMhw9/g+ol926keT1foQFiPGsItjinX/IHCDIEhEm1m0Cozdx4AfZai8QkPqtO064ejkCW4k=").unwrap()),       // n -> modulus
            rsa::BigUint::from_bytes_be(&base64_engine.decode("AQAB").unwrap()),       // e -> pubkey exponent
            rsa::BigUint::from_bytes_be(&base64_engine.decode("YPwEmwjk5HuiROKU4xzHQ6l1hG8Iiha4cKRG3P5W2b66/EN/GUh07ZSf0UiYB67o257jUDVEgwCuPJz776zfApcCB4oGV+YDyEu7Hp/rL8KcSN0la0k2r9scKwxTp4BTJT23zyBFXsV/1wRDK1A5NxsHPDMYi2SoK63Enm/1ptk=").unwrap()),       // d -> privkey exponent
            vec![
                rsa::BigUint::from_bytes_be(&base64_engine.decode("/wjOG+fD0ybNoSRn7nQ79udGeR1b0YhUA5mNjDx/x2fxtIXzygYk0Rhx9QFfDy6LOBvz92gbNQlzCLz3DJt5hw==").unwrap()),
                rsa::BigUint::from_bytes_be(&base64_engine.decode("wHZsJ8OGhkp5p3mrJFZXMDc2mbYusDVTA+t+iRPdS797Tj0pjvU2HN4vTnTj8KBQp6hmnY7dLp9Y1qserySGbw==").unwrap()),
            ], // primes
        ).expect("Failed to create RSA private key from components");

        assert_eq!(
            private_key.to_public_key().e(),
            &rsa::BigUint::from(65537_u32)
        );

        let rrsig = RRSIG::from_dnskey(
            &dnskey,
            &set,
            &(UNIX_EPOCH + Duration::from_millis(1293942305)),
            &(UNIX_EPOCH + Duration::from_millis(1296534305)),
            private_key.to_pkcs8_der().unwrap().as_bytes(),
        )
        .expect("Failed to create RRSIG record from DNSKEY");

        assert_eq!(rrsig.key_tag(), 37350);

        let verified = rrsig
            .verify(&dnskey, &set)
            .expect("Verification process failed");
        assert!(verified);
    }

    #[test]
    fn build_rrsig_ecdsa_p384() {
        use ring::signature::KeyPair;
        use std::time::{Duration, UNIX_EPOCH};

        let set_name = FQDN::from("miek.nl");
        let srv = RecordData::SRV {
            priority: 1000,
            weight: 800,
            port: 0,
            target: FQDN::from("web1.miek.nl"),
        };
        let set = ResourceRecordSet::new(
            &set_name,
            RecordType::SRV,
            RecordClass::IN,
            14400,
            vec![&srv],
        );

        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            pkcs8_bytes.as_ref(),
            &rng,
        )
        .unwrap();

        let mut dnskey = DNSKEY::new(
            rdata::dnssec::Algorithm::ECDSA_P384,
            key_pair.public_key().as_ref().to_vec(),
        );
        dnskey.set_zone_key(true);

        let rrsig = RRSIG::from_dnskey(
            &dnskey,
            &set,
            &(UNIX_EPOCH + Duration::from_millis(1293942305)),
            &(UNIX_EPOCH + Duration::from_millis(1296534305)),
            pkcs8_bytes.as_ref(),
        )
        .expect("Failed to create RRSIG record from DNSKEY");

        let verified = rrsig.verify(&dnskey, &set).expect("Verification failed");
        assert!(verified);
    }

    #[test]
    fn build_rrsig_ed22519() {
        use ring::signature::KeyPair;
        use std::time::{Duration, UNIX_EPOCH};

        let set_name = FQDN::from("miek.nl");
        let srv = RecordData::SRV {
            priority: 1000,
            weight: 800,
            port: 0,
            target: FQDN::from("web1.miek.nl"),
        };
        let set = ResourceRecordSet::new(
            &set_name,
            RecordType::SRV,
            RecordClass::IN,
            14400,
            vec![&srv],
        );

        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

        let mut dnskey = DNSKEY::new(
            rdata::dnssec::Algorithm::ED25519,
            key_pair.public_key().as_ref().to_vec(),
        );
        dnskey.set_zone_key(true);

        let rrsig = RRSIG::from_dnskey(
            &dnskey,
            &set,
            &(UNIX_EPOCH + Duration::from_millis(1293942305)),
            &(UNIX_EPOCH + Duration::from_millis(1296534305)),
            pkcs8_bytes.as_ref(),
        )
        .expect("Failed to create RRSIG record from DNSKEY");

        let verified = rrsig.verify(&dnskey, &set).expect("Verification failed");
        assert!(verified);
    }

    #[test]
    fn build_rrsig_ed448() {
        use crrl::ed448::PrivateKey;
        use std::time::{Duration, UNIX_EPOCH};

        let set_name = FQDN::from("miek.nl");
        let srv = RecordData::SRV {
            priority: 1000,
            weight: 800,
            port: 0,
            target: FQDN::from("web1.miek.nl"),
        };
        let set = ResourceRecordSet::new(
            &set_name,
            RecordType::SRV,
            RecordClass::IN,
            14400,
            vec![&srv],
        );

        let private_key = PrivateKey::decode(&[
            0xcd, 0x23, 0xd2, 0x4f, 0x71, 0x42, 0x74, 0xe7, 0x44, 0x34, 0x32, 0x37, 0xb9, 0x32,
            0x90, 0xf5, 0x11, 0xf6, 0x42, 0x5f, 0x98, 0xe6, 0x44, 0x59, 0xff, 0x20, 0x3e, 0x89,
            0x85, 0x08, 0x3f, 0xfd, 0xf6, 0x05, 0x00, 0x55, 0x3a, 0xbc, 0x0e, 0x05, 0xcd, 0x02,
            0x18, 0x4b, 0xdb, 0x89, 0xc4, 0xcc, 0xd6, 0x7e, 0x18, 0x79, 0x51, 0x26, 0x7e, 0xb3,
            0x28,
        ])
        .expect("Failed to decode ed448 private key data from bytes");

        let mut dnskey = DNSKEY::new(
            rdata::dnssec::Algorithm::ED448,
            private_key.public_key.encode().to_vec(),
        );
        dnskey.set_zone_key(true);

        let rrsig = RRSIG::from_dnskey(
            &dnskey,
            &set,
            &(UNIX_EPOCH + Duration::from_millis(1293942305)),
            &(UNIX_EPOCH + Duration::from_millis(1296534305)),
            &private_key.encode(),
        )
        .expect("Failed to create RRSIG record from DNSKEY");

        let verified = rrsig.verify(&dnskey, &set).expect("Verification failed");
        assert!(verified);
    }
}
