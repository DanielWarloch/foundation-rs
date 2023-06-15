// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use minicbor::data::Type;
use minicbor::decode::Error;
use minicbor::encode::Write;
use minicbor::{Decode, Decoder, Encode, Encoder};

/// Elliptic Curve (EC) key.
#[doc(alias("crypto-eckey"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoECKey<'a> {
    /// The curve type.
    pub curve: u64,
    /// Private key?
    pub is_private: bool,
    /// The key material.
    pub data: &'a [u8],
}

impl<'a> CryptoECKey<'a> {
    /// `secp256k1` curve type.
    pub const SECP256K1: u64 = 0;
}

impl<'b, C> Decode<'b, C> for CryptoECKey<'b> {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        let mut curve = Self::SECP256K1;
        let mut is_private = false;
        let mut data = None;

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
                1 => curve = d.u64()?,
                2 => is_private = d.bool()?,
                3 => data = Some(d.bytes()?),
                _ => return Err(Error::message("unknown map entry")),
            }
        }

        Ok(Self {
            curve,
            is_private,
            data: data.ok_or_else(|| Error::message("data is missing"))?,
        })
    }
}

impl<'a, C> Encode<C> for CryptoECKey<'a> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let is_not_default_curve = self.curve != Self::SECP256K1;
        let is_not_default_private = self.is_private != false;

        let len = is_not_default_curve as u64 + is_not_default_private as u64 + 1;
        e.map(len)?;

        if is_not_default_curve {
            e.u8(1)?.u64(self.curve)?;
        }

        if is_not_default_private {
            e.u8(2)?.bool(self.is_private)?;
        }

        e.u8(3)?.bytes(self.data)?;

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use foundation_test_vectors::{URVector, UR};

    #[test]
    fn test_roundtrip() {
        let vectors = URVector::new();

        for vector in vectors
            .iter()
            .filter(|v| matches!(v.ur, UR::CryptoECKey(_)))
        {
            let crypto_eckey_vector = vector.ur.unwrap_crypto_eckey();

            let crypto_eckey = CryptoECKey {
                curve: CryptoECKey::SECP256K1,
                is_private: crypto_eckey_vector.is_private,
                data: &crypto_eckey_vector.data,
            };

            let cbor = minicbor::to_vec(&crypto_eckey).unwrap();
            assert_eq!(vector.as_cbor, cbor);
        }
    }
}