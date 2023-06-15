// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::num::NonZeroU32;

use minicbor::{
    bytes::DecodeBytes, data::Tag, data::Type, decode::Error, encode::Write, Decode, Decoder,
    Encode, Encoder,
};

use crate::registry::{CryptoCoinInfo, CryptoKeypath};

/// HD Key.
#[doc(alias("hd-key"))]
#[derive(Debug)]
pub enum CryptoHDKey<'a> {
    /// Master key.
    MasterKey(MasterKey),
    /// Derived key.
    DerivedKey(DerivedKey<'a>),
}

#[cfg(feature = "bitcoin")]
impl<'a> TryFrom<&'a bitcoin::bip32::ExtendedPrivKey> for CryptoHDKey<'a> {
    type Error = InterpretExtendedKeyError;

    fn try_from(xprv: &'a bitcoin::bip32::ExtendedPrivKey) -> Result<Self, Self::Error> {
        use crate::registry::CoinType;

        if xprv.depth == 0 {
            Ok(Self::MasterKey(MasterKey {
                key_data: xprv.private_key.secret_bytes(),
                chain_code: xprv.chain_code.to_bytes(),
            }))
        } else {
            let mut key_data = [0u8; 33];
            key_data[0] = 0;
            key_data[1..].copy_from_slice(&xprv.private_key.secret_bytes());

            Ok(Self::DerivedKey(DerivedKey {
                is_private: true,
                key_data,
                chain_code: Some(xprv.chain_code.to_bytes()),
                use_info: Some(CryptoCoinInfo::new(
                    CoinType::BTC,
                    match xprv.network {
                        bitcoin::Network::Bitcoin => CryptoCoinInfo::NETWORK_MAINNET,
                        bitcoin::Network::Testnet => CryptoCoinInfo::NETWORK_BTC_TESTNET,
                        _ => return Err(InterpretExtendedKeyError),
                    },
                )),
                origin: None,
                children: None,
                parent_fingerprint: NonZeroU32::new(u32::from_be_bytes(
                    xprv.parent_fingerprint.to_bytes(),
                )),
                name: None,
                note: None,
            }))
        }
    }
}

#[cfg(feature = "bitcoin")]
impl<'a> TryFrom<&'a bitcoin::bip32::ExtendedPubKey> for CryptoHDKey<'a> {
    type Error = InterpretExtendedKeyError;

    fn try_from(xpub: &'a bitcoin::bip32::ExtendedPubKey) -> Result<Self, Self::Error> {
        use crate::registry::CoinType;

        Ok(Self::DerivedKey(DerivedKey {
            is_private: false,
            key_data: xpub.public_key.serialize(),
            chain_code: Some(xpub.chain_code.to_bytes()),
            use_info: Some(CryptoCoinInfo::new(
                CoinType::BTC,
                match xpub.network {
                    bitcoin::Network::Bitcoin => CryptoCoinInfo::NETWORK_MAINNET,
                    bitcoin::Network::Testnet => CryptoCoinInfo::NETWORK_BTC_TESTNET,
                    _ => return Err(InterpretExtendedKeyError),
                },
            )),
            origin: None,
            children: None,
            parent_fingerprint: NonZeroU32::new(u32::from_be_bytes(
                xpub.parent_fingerprint.to_bytes(),
            )),
            name: None,
            note: None,
        }))
    }
}

#[cfg(feature = "bitcoin")]
#[derive(Debug)]
pub struct InterpretExtendedKeyError;

impl<'b, C> Decode<'b, C> for CryptoHDKey<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        if MasterKey::decode(&mut d.probe(), ctx).is_ok() {
            return Ok(CryptoHDKey::MasterKey(MasterKey::decode(d, ctx)?));
        }

        if DerivedKey::decode(&mut d.probe(), ctx).is_ok() {
            return Ok(CryptoHDKey::DerivedKey(DerivedKey::decode(d, ctx)?));
        }

        Err(Error::message(
            "couldn't decode as master-key or derived-key",
        ))
    }
}

impl<'a, C> Encode<C> for CryptoHDKey<'a> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            CryptoHDKey::MasterKey(master_key) => master_key.encode(e, ctx),
            CryptoHDKey::DerivedKey(derived_key) => derived_key.encode(e, ctx),
        }
    }
}

/// A master key.
#[doc(alias("master-key"))]
#[derive(Debug, Eq, PartialEq)]
pub struct MasterKey {
    /// Key date bytes.
    pub key_data: [u8; 32],
    /// Chain code bytes.
    pub chain_code: [u8; 32],
}

impl<'b, C> Decode<'b, C> for MasterKey {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        let mut is_master = None;
        let mut key_data = None;
        let mut chain_code = None;

        let mut len = d.map()?;
        loop {
            match len {
                Some(n) if n == 0 => break,
                Some(n) => len = Some(n - 1),
                None => {
                    if d.datatype()? == Type::Break {
                        break;
                    }
                }
            }

            match d.u32()? {
                1 => is_master = Some(d.bool()?),
                3 => {
                    let mut data = [0; 32];

                    let bytes: [u8; 33] = DecodeBytes::decode_bytes(d, ctx)?;
                    data.copy_from_slice(&bytes[..32]);
                    key_data = Some(data)
                }
                4 => chain_code = Some(DecodeBytes::decode_bytes(d, ctx)?),
                _ => return Err(Error::message("unknown map entry")),
            }
        }

        match is_master {
            Some(true) => (),
            Some(false) => return Err(Error::message("is-master is false")),
            None => return Err(Error::message("is-master is not present")),
        }

        Ok(Self {
            key_data: key_data.ok_or_else(|| Error::message("key-data is not present"))?,
            chain_code: chain_code.ok_or_else(|| Error::message("chain-code is not present"))?,
        })
    }
}

impl<C> Encode<C> for MasterKey {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let mut key_data = [0; 33];
        key_data[0] = 0;
        key_data[1..].copy_from_slice(&self.key_data);

        e.map(3)?
            .u8(1)?
            .bool(true)?
            .u8(3)?
            .bytes(&key_data)?
            .u8(4)?
            .bytes(&self.chain_code)?;

        Ok(())
    }
}

/// A derived key.
#[doc(alias("derived-key"))]
#[derive(Debug)]
pub struct DerivedKey<'a> {
    /// `true` if key is private, `false` if public.
    pub is_private: bool,
    /// Key data bytes.
    pub key_data: [u8; 33],
    /// Optional chain code.
    pub chain_code: Option<[u8; 32]>,
    /// How the key is to be used.
    pub use_info: Option<CryptoCoinInfo>,
    /// How the key was derived.
    pub origin: Option<CryptoKeypath<'a>>,
    /// What children should/can be derived from this.
    pub children: Option<CryptoKeypath<'a>>,
    /// The fingerprint of this key's direct ancestor.
    pub parent_fingerprint: Option<NonZeroU32>,
    /// A short name for this key.
    pub name: Option<&'a str>,
    /// An arbitrary amount of text describing the key.
    pub note: Option<&'a str>,
}

impl<'b, C> Decode<'b, C> for DerivedKey<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        let mut is_private = false;
        let mut key_data = None;
        let mut chain_code = None;
        let mut use_info = None;
        let mut origin = None;
        let mut children = None;
        let mut parent_fingerprint = None;
        let mut name = None;
        let mut note = None;

        let mut len = d.map()?;
        loop {
            match len {
                Some(n) if n == 0 => break,
                Some(n) => len = Some(n - 1),
                None => {
                    if d.datatype()? == Type::Break {
                        break;
                    }
                }
            }

            match d.u32()? {
                2 => is_private = d.bool()?,
                3 => key_data = Some(DecodeBytes::decode_bytes(d, ctx)?),
                4 => chain_code = Some(DecodeBytes::decode_bytes(d, ctx)?),
                5 => match d.tag()? {
                    Tag::Unassigned(305) => use_info = Some(CryptoCoinInfo::decode(d, ctx)?),
                    _ => return Err(Error::message("invalid tag for crypto-coininfo")),
                },
                6 => match d.tag()? {
                    Tag::Unassigned(304) => origin = Some(CryptoKeypath::decode(d, ctx)?),
                    _ => return Err(Error::message("invalid tag for crypto-keypath")),
                },
                7 => match d.tag()? {
                    Tag::Unassigned(304) => children = Some(CryptoKeypath::decode(d, ctx)?),
                    _ => return Err(Error::message("invalid tag for crypto-keypath")),
                },
                8 => {
                    parent_fingerprint = Some(
                        NonZeroU32::new(d.u32()?)
                            .ok_or_else(|| Error::message("parent-fingerprint is zero"))?,
                    )
                }
                9 => name = Some(d.str()?),
                10 => note = Some(d.str()?),
                _ => return Err(Error::message("unknown map entry")),
            }
        }

        Ok(Self {
            is_private,
            key_data: key_data.ok_or_else(|| Error::message("key-data is not present"))?,
            chain_code,
            use_info,
            origin,
            children,
            parent_fingerprint,
            name,
            note,
        })
    }
}

impl<'a, C> Encode<C> for DerivedKey<'a> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let len = self.is_private as u64
            + 1
            + self.chain_code.is_some() as u64
            + self.use_info.is_some() as u64
            + self.origin.is_some() as u64
            + self.children.is_some() as u64
            + self.parent_fingerprint.is_some() as u64
            + self.name.is_some() as u64
            + self.note.is_some() as u64;

        e.map(len)?;

        if self.is_private {
            e.u8(2)?.bool(self.is_private)?;
        }

        e.u8(3)?.bytes(&self.key_data)?;

        if let Some(ref chain_code) = self.chain_code {
            e.u8(4)?.bytes(chain_code)?;
        }

        if let Some(ref use_info) = self.use_info {
            e.u8(5)?.tag(Tag::Unassigned(305))?;
            use_info.encode(e, ctx)?;
        }

        if let Some(ref origin) = self.origin {
            e.u8(6)?.tag(Tag::Unassigned(304))?;
            origin.encode(e, ctx)?;
        }

        if let Some(ref children) = self.children {
            e.u8(7)?.tag(Tag::Unassigned(304))?;
            children.encode(e, ctx)?;
        }

        if let Some(parent_fingerprint) = self.parent_fingerprint {
            e.u8(8)?.u32(parent_fingerprint.get())?;
        }

        if let Some(name) = self.name {
            e.u8(9)?.str(name)?;
        }

        if let Some(note) = self.note {
            e.u8(10)?.str(note)?;
        }

        Ok(())
    }
}