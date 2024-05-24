// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::marker::PhantomData;
use std::mem::MaybeUninit;

use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sha::Sha256;
use openssl::sign::Signer;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use spdm_types::crypto::{
    AesGcm128Iv, AesGcm128Tag, EcP256UncompressedPoint, EcdsaP256Signature, Sha256Hash,
    AES_GCM_128_IV_SIZE, AES_GCM_128_KEY_SIZE, ECDSA_P256_SCALAR_SIZE, EC_P256_COORD_SIZE,
    SHA256_HASH_SIZE,
};
use spdm_types::deps::{Crypto, CryptoError, CryptoResult, CryptoStatus, IdentityPublicKey};
use uninit::extension_traits::AsOut;
use uninit::out_ref::Out;

pub struct RawKey<T> {
    pub vec: Vec<u8>,
    phantom: PhantomData<T>,
}

impl<T> RawKey<T> {
    fn new(vec: Vec<u8>) -> Self {
        Self {
            vec,
            phantom: PhantomData,
        }
    }
}

pub struct IdentityPrivateKeyTag;
pub struct HmacDerivationKeyTag;
pub struct HmacSecretKeyTag;
pub struct AesGcmKeyTag;

trait ToCryptoResult<T> {
    fn map_err_crypto(self) -> CryptoResult<T>;
}

impl<T, E> ToCryptoResult<T> for Result<T, E> {
    fn map_err_crypto(self) -> CryptoResult<T> {
        self.map_err(|_| CryptoError)
    }
}

pub struct CryptoImpl;

fn hmac_expand_vec<'a, T, U>(
    prk: &RawKey<T>,
    info: &[u8],
    output: Out<'a, RawKey<U>>,
    length: usize,
) -> CryptoResult<&'a mut RawKey<U>> {
    // We only need to support HKDF-Expand that will be completed in 1 round.
    if length > SHA256_HASH_SIZE {
        return Err(CryptoError);
    }

    let key = PKey::hmac(&prk.vec).map_err_crypto()?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key).map_err_crypto()?;
    signer.update(info).map_err_crypto()?;
    signer.update(&[0x01]).map_err_crypto()?;
    let mut result = signer.sign_to_vec().map_err_crypto()?;
    result.truncate(length);
    Ok(output.write(RawKey::new(result)))
}

impl CryptoImpl {
    pub fn is_public_key_valid(public_key: &EcP256UncompressedPoint) -> CryptoResult<bool> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err_crypto()?;
        let mut ctx = BigNumContext::new().map_err_crypto()?;
        let x = BigNum::from_slice(&public_key.x).map_err_crypto()?;
        let y = BigNum::from_slice(&public_key.y).map_err_crypto()?;
        let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y).map_err_crypto()?;
        key.public_key()
            .is_on_curve(&group, &mut ctx)
            .map_err_crypto()
    }
}

unsafe impl Crypto for CryptoImpl {
    type IdentityPrivateKeyHandle = RawKey<IdentityPrivateKeyTag>;
    type Sha256HashContext = Sha256;
    type HmacDerivationKeyHandle = RawKey<HmacDerivationKeyTag>;
    type HmacSecretKeyHandle = RawKey<HmacSecretKeyTag>;
    type AesGcmKeyHandle = RawKey<AesGcmKeyTag>;

    fn sha256_init(
        ctx: Out<Self::Sha256HashContext>,
    ) -> CryptoResult<&mut Self::Sha256HashContext> {
        Ok(ctx.write(Sha256::new()))
    }

    fn sha256_update(ctx: &mut Self::Sha256HashContext, data: &[u8]) -> CryptoStatus {
        ctx.update(data);
        Ok(())
    }

    fn sha256_get<'a>(
        ctx: &Self::Sha256HashContext,
        buf: Out<'a, Sha256Hash>,
    ) -> CryptoResult<&'a mut Sha256Hash> {
        let ctx = ctx.clone();
        let digest = ctx.finish();
        if digest.len() != SHA256_HASH_SIZE {
            return Err(CryptoError);
        }
        Ok(buf.write(digest))
    }

    fn sha256_final(
        ctx: Self::Sha256HashContext,
        buf: Out<Sha256Hash>,
    ) -> CryptoResult<&mut Sha256Hash> {
        let digest = ctx.finish();
        Ok(buf.write(digest))
    }

    fn ecdsa_sign<'a>(
        key_handle: &Self::IdentityPrivateKeyHandle,
        hash_to_sign: &Sha256Hash,
        buf: Out<'a, EcdsaP256Signature>,
    ) -> CryptoResult<&'a mut EcdsaP256Signature> {
        let key = EcKey::private_key_from_der(&key_handle.vec).map_err_crypto()?;
        let sig = EcdsaSig::sign(hash_to_sign, &key).map_err_crypto()?;
        let r = sig.r();
        let s = sig.s();
        // SAFETY: We'll fully initialize both fields of the EcdsaP256Signature.
        let buf = unsafe { buf.assume_init() };
        buf.r.copy_from_slice(
            &r.to_vec_padded(ECDSA_P256_SCALAR_SIZE as i32)
                .map_err_crypto()?,
        );
        buf.s.copy_from_slice(
            &s.to_vec_padded(ECDSA_P256_SCALAR_SIZE as i32)
                .map_err_crypto()?,
        );
        Ok(buf)
    }

    fn ecdsa_verify(
        public_key: &IdentityPublicKey,
        hash_to_sign: &Sha256Hash,
        signature: &EcdsaP256Signature,
    ) -> CryptoStatus {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err_crypto()?;
        let x = BigNum::from_slice(&public_key.x).map_err_crypto()?;
        let y = BigNum::from_slice(&public_key.y).map_err_crypto()?;
        let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y).map_err_crypto()?;

        let r = BigNum::from_slice(&signature.r).map_err_crypto()?;
        let s = BigNum::from_slice(&signature.s).map_err_crypto()?;
        let signature = EcdsaSig::from_private_components(r, s).map_err_crypto()?;

        if !signature.verify(hash_to_sign, &key).map_err_crypto()? {
            return Err(CryptoError);
        }
        Ok(())
    }

    fn hmac_extract_from_ecdh_with_priv<'a>(
        their_public_key: &EcP256UncompressedPoint,
        my_private_key: &Self::IdentityPrivateKeyHandle,
        salt: &[u8],
        hmac_derivation_key_handle: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err_crypto()?;
        let x = BigNum::from_slice(&their_public_key.x).map_err_crypto()?;
        let y = BigNum::from_slice(&their_public_key.y).map_err_crypto()?;
        let their_key: PKey<_> = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
            .and_then(TryInto::try_into)
            .map_err_crypto()?;

        let my_key: PKey<_> = EcKey::private_key_from_der(&my_private_key.vec)
            .and_then(TryInto::try_into)
            .map_err_crypto()?;
        let mut deriver = Deriver::new(&my_key).map_err_crypto()?;
        deriver.set_peer(&their_key).map_err_crypto()?;
        let shared_secret = deriver.derive_to_vec().map_err_crypto()?;

        let hmac_key = PKey::hmac(salt).map_err_crypto()?;
        let mut signer = Signer::new(MessageDigest::sha256(), &hmac_key).map_err_crypto()?;
        let result = signer
            .sign_oneshot_to_vec(&shared_secret)
            .map_err_crypto()?;
        Ok(hmac_derivation_key_handle.write(RawKey::new(result)))
    }

    fn hmac_extract_from_ecdh<'a, 'b>(
        their_public_key: &EcP256UncompressedPoint,
        salt: &[u8],
        my_public_key: Out<'a, EcP256UncompressedPoint>,
        hmac_derivation_key_handle: Out<'b, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<(
        &'a mut EcP256UncompressedPoint,
        &'b mut Self::HmacDerivationKeyHandle,
    )> {
        let mut private = MaybeUninit::<Self::IdentityPrivateKeyHandle>::uninit();
        let (_, public) = Self::random_key_pair(private.as_out(), my_public_key)?;
        // SAFETY: `private` is guaranteed to be initialized after a successful
        // `random_key_pair`.
        let private = unsafe { private.assume_init() };

        let hmac_key_handle = Self::hmac_extract_from_ecdh_with_priv(
            their_public_key,
            &private,
            salt,
            hmac_derivation_key_handle,
        )?;
        Ok((public, hmac_key_handle))
    }

    fn hmac_extract<'a>(
        hmac_derivation_key_handle_in: &Self::HmacDerivationKeyHandle,
        data: &[u8],
        hmac_derivation_key_handle_out: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle> {
        let key = PKey::hmac(&hmac_derivation_key_handle_in.vec).map_err_crypto()?;
        let mut signer = Signer::new(MessageDigest::sha256(), &key).map_err_crypto()?;
        let result = signer.sign_oneshot_to_vec(data).map_err_crypto()?;
        Ok(hmac_derivation_key_handle_out.write(RawKey::new(result)))
    }

    fn hmac_expand_hmac_secret_key<'a>(
        hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        info: &[u8],
        hmac_secret_key_handle: Out<'a, Self::HmacSecretKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacSecretKeyHandle> {
        hmac_expand_vec(
            hmac_derivation_key_handle,
            info,
            hmac_secret_key_handle,
            SHA256_HASH_SIZE,
        )
    }

    fn hmac_expand_derivation_key<'a>(
        hmac_derivation_key_handle_in: &Self::HmacDerivationKeyHandle,
        info: &[u8],
        hmac_derivation_key_handle_out: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle> {
        hmac_expand_vec(
            hmac_derivation_key_handle_in,
            info,
            hmac_derivation_key_handle_out,
            SHA256_HASH_SIZE,
        )
    }

    fn hmac_expand_aes_gcm_key<'a>(
        hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        info: &[u8],
        aes_gcm_key: Out<'a, Self::AesGcmKeyHandle>,
    ) -> CryptoResult<&'a mut Self::AesGcmKeyHandle> {
        hmac_expand_vec(
            hmac_derivation_key_handle,
            info,
            aes_gcm_key,
            AES_GCM_128_KEY_SIZE,
        )
    }

    fn hmac_expand_aes_gcm_iv<'a>(
        hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        info: &[u8],
        mut aes_gcm_iv: Out<'a, AesGcm128Iv>,
    ) -> CryptoResult<&'a mut AesGcm128Iv> {
        // We only need to support HKDF-Expand that will be completed in 1 round.
        let key = PKey::hmac(&hmac_derivation_key_handle.vec).map_err_crypto()?;
        let mut signer = Signer::new(MessageDigest::sha256(), &key).map_err_crypto()?;
        signer.update(info).map_err_crypto()?;
        signer.update(&[0x01]).map_err_crypto()?;
        let result = signer.sign_to_vec().map_err_crypto()?;
        if result.len() < AES_GCM_128_IV_SIZE {
            return Err(CryptoError);
        }

        aes_gcm_iv
            .r()
            .as_slice_out()
            .copy_from_slice(&result[..AES_GCM_128_IV_SIZE]);

        // SAFETY: `aes_gcm_iv` is fully initialized after `copy_from_slice`.
        Ok(unsafe { aes_gcm_iv.assume_init() })
    }

    fn hmac<'a>(
        hmac_secret_key_handle: &Self::HmacSecretKeyHandle,
        data: &[u8],
        buf: Out<'a, Sha256Hash>,
    ) -> CryptoResult<&'a mut Sha256Hash> {
        let key = PKey::hmac(&hmac_secret_key_handle.vec).map_err_crypto()?;
        let mut signer = Signer::new(MessageDigest::sha256(), &key).map_err_crypto()?;

        // SAFETY: `hash` will be fully initialized after successful `sign_oneshot`.
        let hash = unsafe { buf.assume_init() };
        assert_eq!(
            signer.sign_oneshot(hash, data).map_err_crypto()?,
            SHA256_HASH_SIZE
        );
        Ok(hash)
    }

    fn validate_hmac(
        hmac_secret_key_handle: &Self::HmacSecretKeyHandle,
        data: &[u8],
        hmac: &Sha256Hash,
    ) -> CryptoStatus {
        let key = PKey::hmac(&hmac_secret_key_handle.vec).map_err_crypto()?;
        let mut signer = Signer::new(MessageDigest::sha256(), &key).map_err_crypto()?;

        let buf = MaybeUninit::<Sha256Hash>::uninit();
        // SAFETY: `hash` will be fully initialized after successful `sign_oneshot`.
        let hash = &mut unsafe { buf.assume_init() };
        assert_eq!(
            signer.sign_oneshot(hash, data).map_err_crypto()?,
            SHA256_HASH_SIZE
        );
        if !memcmp::eq(hmac, hash) {
            return Err(CryptoError);
        }
        Ok(())
    }

    fn aes_gcm_encrypt<'a>(
        aes_gcm_key_handle: &Self::AesGcmKeyHandle,
        iv: &AesGcm128Iv,
        aad: &[u8],
        buf: &mut [u8],
        tag: Out<'a, AesGcm128Tag>,
    ) -> CryptoResult<&'a mut AesGcm128Tag> {
        let cipher = Cipher::aes_128_gcm();
        // SAFETY: `tag` will be fully initialized after successful `encrypt_aead`.
        let tag = unsafe { tag.assume_init() };
        let encrypted = encrypt_aead(cipher, &aes_gcm_key_handle.vec, Some(iv), aad, buf, tag)
            .map_err(|err| {
                println!("{err}, {}", aes_gcm_key_handle.vec.len());
                err
            })
            .map_err_crypto()?;
        buf.copy_from_slice(&encrypted);
        Ok(tag)
    }

    fn aes_gcm_decrypt(
        aes_gcm_key_handle: &Self::AesGcmKeyHandle,
        iv: &AesGcm128Iv,
        aad: &[u8],
        tag: &AesGcm128Tag,
        buf: &mut [u8],
    ) -> CryptoStatus {
        let cipher = Cipher::aes_128_gcm();
        let decrypted = decrypt_aead(cipher, &aes_gcm_key_handle.vec, Some(iv), aad, buf, tag)
            .map_err_crypto()?;
        buf.copy_from_slice(&decrypted);
        Ok(())
    }

    fn random_bytes(buf: Out<[u8]>) -> CryptoResult<&mut [u8]> {
        // SAFETY: `buf` is guaranteed to be initialized after a successful `rand_bytes`.
        let buf = unsafe { buf.assume_init() };
        rand_bytes(buf).map_err_crypto()?;
        Ok(buf)
    }

    fn random_key_pair<'a, 'b>(
        private: Out<'a, Self::IdentityPrivateKeyHandle>,
        public: Out<'b, IdentityPublicKey>,
    ) -> CryptoResult<(
        &'a mut Self::IdentityPrivateKeyHandle,
        &'b mut IdentityPublicKey,
    )> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err_crypto()?;
        let key = EcKey::generate(&group).map_err_crypto()?;

        let private = private.write(RawKey::new(key.private_key_to_der().map_err_crypto()?));

        // SAFETY: We'll fully initialize both fields of the EcP256UncompressedPoint.
        let public = unsafe { public.assume_init() };
        let mut ctx = BigNumContext::new().map_err_crypto()?;
        let mut x = BigNum::new().map_err_crypto()?;
        let mut y = BigNum::new().map_err_crypto()?;
        key.public_key()
            .affine_coordinates(&group, &mut x, &mut y, &mut ctx)
            .map_err_crypto()?;

        public.x.copy_from_slice(
            &x.to_vec_padded(EC_P256_COORD_SIZE as i32)
                .map_err_crypto()?,
        );
        public.y.copy_from_slice(
            &y.to_vec_padded(EC_P256_COORD_SIZE as i32)
                .map_err_crypto()?,
        );

        Ok((private, public))
    }
}
