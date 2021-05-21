//! Network Message
//!
//! This module defines the message types and their traits which are used
//! for (de)serializing revault messages for transmission on the network.
//!
//! Please find the specification at
//! https://github.com/re-vault/practical-revault/blob/master/messages.md

use serde::{Deserialize, Serialize};

/// A JSONRPC-like request, as specified in [practical-revault](https://github.com/revault/practical-revault/blob/master/messages.md)
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Request<'a> {
    WtSig {
        method: &'a str,
        params: watchtower::Sig,
        id: u32,
    },
    SetSpendTx {
        method: &'a str,
        params: coordinator::SetSpendTx,
        id: u32,
    },
    GetSpendTx {
        method: &'a str,
        params: coordinator::GetSpendTx,
        id: u32,
    },
    CoordSig {
        method: &'a str,
        params: coordinator::Sig,
        id: u32,
    },
    GetSigs {
        method: &'a str,
        params: coordinator::GetSigs,
        id: u32,
    },
    Sign {
        method: &'a str,
        params: cosigner::SignRequest,
        id: u32,
    },
}

impl<'a> Request<'a> {
    /// Get the parameters of this request
    pub fn params(self) -> RequestParams {
        match self {
            Request::WtSig { params, .. } => RequestParams::WtSig(params),
            Request::SetSpendTx { params, .. } => RequestParams::SetSpendTx(params),
            Request::GetSpendTx { params, .. } => RequestParams::GetSpendTx(params),
            Request::CoordSig { params, .. } => RequestParams::CoordSig(params),
            Request::GetSigs { params, .. } => RequestParams::GetSigs(params),
            Request::Sign { params, .. } => RequestParams::Sign(params),
        }
    }

    /// Get the id of this request
    pub fn id(&self) -> u32 {
        match self {
            Request::WtSig { id, .. } => *id,
            Request::SetSpendTx { id, .. } => *id,
            Request::GetSpendTx { id, .. } => *id,
            Request::CoordSig { id, .. } => *id,
            Request::GetSigs { id, .. } => *id,
            Request::Sign { id, .. } => *id,
        }
    }
}

/// All params types that can possibly be sent through a Request
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RequestParams {
    WtSig(watchtower::Sig),
    SetSpendTx(coordinator::SetSpendTx),
    GetSpendTx(coordinator::GetSpendTx),
    CoordSig(coordinator::Sig),
    GetSigs(coordinator::GetSigs),
    Sign(cosigner::SignRequest),
}

// Implement From(param type) for a Request
macro_rules! impl_to_request {
    ($message_struct:ident, $message_name:literal, $enum_variant:ident) => {
        impl From<$message_struct> for Request<'_> {
            fn from(params: $message_struct) -> Self {
                Self::$enum_variant {
                    method: $message_name,
                    params,
                    id: sodiumoxide::randombytes::randombytes_uniform(u32::MAX),
                }
            }
        }
    };
}

/// All result types that can possibly be returned by a Response
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ResponseResult {
    WtSig(watchtower::SigResult),
    Sigs(coordinator::Sigs),
    Sig(coordinator::SigResult),
    SetSpend(coordinator::SetSpendResult),
    SpendTx(coordinator::SpendTx),
    SignResult(cosigner::SignResult),
}

/// A JSONRPC-like response, as specified in [practical-revault](https://github.com/revault/practical-revault/blob/master/messages.md)
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
pub struct Response<T> {
    pub result: T,
    pub id: u32,
}

/// Messages related to the communication with the Watchtower(s)
pub mod watchtower {
    use super::{Deserialize, Request, Serialize};
    use bitcoin::{
        hash_types::Txid,
        secp256k1::{key::PublicKey, Signature},
        OutPoint,
    };
    use std::collections::BTreeMap;
    use std::convert::From;

    /// Message from a stakeholder to share all signatures for a revocation
    /// transaction with its watchtower.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct Sig {
        /// A sufficient set of public keys and associated ALL|ANYONECANPAY
        /// bitcoin ECDSA signatures to validate the revocation transaction
        pub signatures: BTreeMap<PublicKey, Signature>,
        /// Revocation transaction id
        pub txid: Txid,
        /// Deposit outpoint of this vault
        pub deposit_outpoint: OutPoint,
    }
    impl_to_request!(Sig, "sig", WtSig);

    /// Message from the watchtower to stakeholder to acknowledge that it has
    /// sufficient signatures and fees to begin guarding the vault with the
    /// revocation transaction
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct SigResult {
        /// Result of acknowledgement
        pub ack: bool,
        // FIXME: we don't need it anymore once we have ids in messages
        /// Revocation transaction id
        pub txid: Txid,
    }
}

/// Messages related to the communication with the Coordinator
pub mod coordinator {
    use super::{Deserialize, Request, Serialize};
    use bitcoin::{
        hash_types::Txid,
        secp256k1::{key::PublicKey, Signature},
        OutPoint, Transaction,
    };
    use revault_tx::transactions::{RevaultTransaction, SpendTransaction};
    use std::collections::BTreeMap;
    use std::convert::From;

    mod serde_tx_hex {
        use revault_tx::bitcoin::{
            consensus::encode,
            hashes::hex::{FromHex, ToHex},
            Transaction,
        };
        use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S>(tx: &Transaction, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let hex_str = encode::serialize(tx).to_hex();
            hex_str.serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Transaction, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let bytes = Vec::from_hex(&s).map_err(serde::de::Error::custom)?;
            encode::deserialize::<Transaction>(&bytes).map_err(serde::de::Error::custom)
        }
    }

    /// Sent by a wallet to retrieve all signatures for a specific transaction
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct GetSigs {
        /// Transaction id
        pub id: Txid,
    }
    impl_to_request!(GetSigs, "get_sigs", GetSigs);

    /// Message response to get_sigs from sync server to wallet client with a
    /// (potentially incomplete) mapping of each public key to each signature
    /// required to verify this **usual** transaction
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct Sigs {
        /// Mapping of public keys to ECDSA signatures for the requested usual
        /// transaction.
        pub signatures: BTreeMap<PublicKey, Signature>,
    }

    /// Sent by a manager to advertise the spend transaction that will eventually
    /// be used for a specific unvault.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct SetSpendTx {
        /// Deposit outpoints of the vault this transaction is spending
        pub deposit_outpoints: Vec<OutPoint>,
        /// Fully signed spend transaction, as hex
        #[serde(with = "serde_tx_hex")]
        transaction: Transaction,
    }
    impl_to_request!(SetSpendTx, "set_spend_tx", SetSpendTx);

    impl SetSpendTx {
        /// Create a SetSpendTx message out of a SpendTransaction.
        ///
        /// The SpendTransaction MUST have been finalized beforehand or it'll panic.
        pub fn from_spend_tx(deposit_outpoints: Vec<OutPoint>, tx: SpendTransaction) -> Self {
            assert!(tx.is_finalized());
            let transaction = tx.into_psbt().extract_tx();
            Self {
                deposit_outpoints,
                transaction,
            }
        }

        /// Get the raw spend transaction
        pub fn spend_tx(self) -> Transaction {
            self.transaction
        }
    }

    /// Response to [SetSpendTx] by the coordinator, `ack` is `true` if it claims to have
    /// succesfully stored the Spend tx.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct SetSpendResult {
        /// Result of acknowledgement
        pub ack: bool,
    }

    /// Sent by a watchtower to the synchronisation server after an unvault
    /// event to learn about the spend transaction.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct GetSpendTx {
        /// Outpoint designing the deposit utxo that created the vault this
        /// spend tx is spending.
        pub deposit_outpoint: OutPoint,
    }
    impl_to_request!(GetSpendTx, "get_spend_tx", GetSpendTx);

    /// The response to the [GetSpendTx] request.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct SpendTx {
        /// The Bitcoin-serialized Spend transaction. The sync server isn't
        /// creating it so there is no point to create it from_spend_tx().
        #[serde(with = "serde_tx_hex")]
        pub transaction: Transaction,
    }

    /// Message from a stakeholder client to sync server to share (at any time)
    /// the signature for a revocation transaction with all participants.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct Sig {
        /// Secp256k1 public key used to sign the transaction (hex)
        pub pubkey: PublicKey,
        /// Bitcoin ECDSA signature as hex
        pub signature: Signature,
        /// Txid of the transaction the signature applies to
        pub id: Txid,
    }
    impl_to_request!(Sig, "sig", CoordSig);

    /// Response to [SigResult] by the coordinator, `ack` is `true` if it claims to have
    /// succesfully stored the Spend tx.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct SigResult {
        /// Result of acknowledgement
        pub ack: bool,
    }
}

/// Messages related to the communication with the Cosigning Server(s)
pub mod cosigner {
    use super::{Deserialize, Request, Serialize};
    use revault_tx::transactions::SpendTransaction;
    use std::convert::From;

    /// Message from a manager to a cosigning server who will soon attempt to
    /// unvault and spend a vault utxo
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct SignRequest {
        /// The partially signed unvault transaction
        pub tx: SpendTransaction,
    }
    impl_to_request!(SignRequest, "sign", Sign);

    /// Message returned from the cosigning server to the manager containing
    /// the requested signature
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct SignResult {
        /// Cosigning server's signature for the unvault transaction
        pub tx: Option<SpendTransaction>,
    }
}

#[cfg(test)]
mod tests {
    use super::{Request, Response, ResponseResult};
    use std::{collections::BTreeMap, str::FromStr};

    use revault_tx::{
        bitcoin::{
            hash_types::Txid,
            secp256k1::{
                key::{PublicKey, SecretKey},
                Secp256k1, Signature,
            },
            OutPoint,
        },
        transactions::{RevaultTransaction, SpendTransaction},
    };

    use super::coordinator;
    use super::cosigner;
    use super::watchtower;

    fn get_dummy_pubkey() -> PublicKey {
        let secp_ctx = Secp256k1::new();
        PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap())
    }

    fn get_dummy_sig() -> Signature {
        // from https://github.com/rust-bitcoin/rust-secp256k1/blob/master/src/lib.rs
        Signature::from_compact(&[
            0xdc, 0x4d, 0xc2, 0x64, 0xa9, 0xfe, 0xf1, 0x7a, 0x3f, 0x25, 0x34, 0x49, 0xcf, 0x8c,
            0x39, 0x7a, 0xb6, 0xf1, 0x6f, 0xb3, 0xd6, 0x3d, 0x86, 0x94, 0x0b, 0x55, 0x86, 0x82,
            0x3d, 0xfd, 0x02, 0xae, 0x3b, 0x46, 0x1b, 0xb4, 0x33, 0x6b, 0x5e, 0xcb, 0xae, 0xfd,
            0x66, 0x27, 0xaa, 0x92, 0x2e, 0xfc, 0x04, 0x8f, 0xec, 0x0c, 0x88, 0x1c, 0x10, 0xc4,
            0xc9, 0x42, 0x8f, 0xca, 0x69, 0xc1, 0x32, 0xa2,
        ])
        .expect("compact signatures are 64 bytes; DER signatures are 68-72 bytes")
    }

    fn get_dummy_spend_tx() -> SpendTransaction {
        let psbt_base64 = "cHNidP8BAGcCAAAAAY74R7yfKjYatj96vo5Ww2nRXnMLqJZ0sJtCZ0vUDJT1AAAAAADNVgAAAoDYAQAAAAAAIgAgrhve44jyE2BUeXInsUqYPSjeKfUi8+vcTiX9K649nlIBAAAAAAAAAAAAAAAAAAEBK6BK9QUAAAAAIgAgGOT4nZS2eDtYm83Cvrva0Ozxmrw4Wjin73s81+Z/MfEBAwQBAAAAAQX9YgJTIQJXWghCPRbOUhpx+hi93OfpK75maJRYRC38QR4f7+NtFiECM9/45YqHN25XccUBgRIDEcbyVEgt7j61+c9r3RZ7FzohAriewns/EcwKUVDvv1bxr790pkzQRzmqfV3dQ9mzBjaQU65kdqkUqOUtXIDgEzokTmljuXvjUVK6PKqIrGt2qRSxhJ72lPFm92bL1zs0fxxSxgvWIIisbJNrdqkUH5eaO3DdSZU5iyaVBAxs4jQpiiaIrGyTa3apFORRbu2KExrgnCCww5w9TraaoolAiKxsk2t2qRTdO8BPO/zd71a6yb+Cns88TZKG84isbJNrdqkU32Y5t5RL0rYBZZvHWmii6eTcgZ+IrGyTa3apFK83DFJxO+ke61QLvGNyYnmSwKrDiKxsk2t2qRQOTi7K/HfcXcC5iBLjCnMWcMWjIYisbJNYh2dYIQLR/ezgE85uXQeHPU/DkO9OMViCc8qtX1GT1B+pC3O4ASECx3y8Y+ejFiUsobbCiYlAU3h87Q7y+QhADwLFygARZXchAiQAGsW+t/RQ0AJ1axuUM9e58WBlzItzzI4xB8sPnMrsIQKnh96esMFOEyF0tbKBXWmAtff+mxSOoyQVefv/JN/vhSEDiQaTfG58TKdD2N4DbB+wCd3Sz04D4Psle+84rmIW51ghAzFWj+Qs+0gWprDMs3Aat9f5wMZuZaZth1AAtHbe2NbxIQL8522r0lMYLHkL+h2yus2uJP8y6N28+cwpWyaTFNnP+CECdjQgoJBQYwTi7KPMwt1RBcdP0KnnWdYNCSkUmtF972hYrwLOVrJoAAEBaVEhAldaCEI9Fs5SGnH6GL3c5+krvmZolFhELfxBHh/v420WIQIz3/jlioc3bldxxQGBEgMRxvJUSC3uPrX5z2vdFnsXOiECuJ7Cez8RzApRUO+/VvGvv3SmTNBHOap9Xd1D2bMGNpBTrgAA";
        serde_json::from_str(&serde_json::to_string(&psbt_base64).unwrap()).unwrap()
    }

    macro_rules! roundtrip {
        ($msg:ident) => {
            let serialized_msg = serde_json::to_string(&$msg).unwrap();
            let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();
            assert_eq!($msg, deserialized_msg);
            assert_eq!(
                serialized_msg,
                String::from_utf8_lossy(&serde_json::to_vec(&$msg).unwrap())
            );
        };
    }

    macro_rules! assert_str_ser {
        ($msg:ident, $str:expr) => {
            let ser = serde_json::to_string(&$msg).unwrap();
            assert_eq!(ser, $str);
        };
    }

    #[test]
    fn serde_watchtower_sig() {
        let pubkey: PublicKey = get_dummy_pubkey();
        let sig: Signature = get_dummy_sig();
        let signatures: BTreeMap<PublicKey, Signature> = [(pubkey, sig)].iter().cloned().collect();
        let txid = Txid::default();
        let deposit_outpoint = OutPoint::from_str(
            "3694ef9e8fcd78e9b8165a41e6f5e2b5f10bcd92c6d6e42b3325a850df56cd83:0",
        )
        .unwrap();
        let msg = watchtower::Sig {
            signatures,
            txid,
            deposit_outpoint,
        };
        let req = Request::from(msg);
        roundtrip!(req);
        assert_str_ser!(
            req,
            format!("{{\"method\":\"sig\",\"params\":{{\"signatures\":{{\"035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c\":\"3045022100dc4dc264a9fef17a3f253449cf8c397ab6f16fb3d63d86940b5586823dfd02ae02203b461bb4336b5ecbaefd6627aa922efc048fec0c881c10c4c9428fca69c132a2\"}},\"txid\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"deposit_outpoint\":\"3694ef9e8fcd78e9b8165a41e6f5e2b5f10bcd92c6d6e42b3325a850df56cd83:0\"}},\"id\":{}}}", req.id())
            );
    }

    #[test]
    fn serde_watchtower_sig_ack() {
        let ack = true;
        let txid = Txid::default();
        let msg = Response {
            result: ResponseResult::WtSig(watchtower::SigResult { ack, txid }),
            id: 1946,
        };
        roundtrip!(msg);
        assert_str_ser!(
            msg,
            r#"{"result":{"ack":true,"txid":"0000000000000000000000000000000000000000000000000000000000000000"},"id":1946}"#
        );
    }

    #[test]
    fn serde_watchtower_get_spend_tx() {
        let msg = coordinator::GetSpendTx {
            deposit_outpoint: OutPoint::from_str(
                "6a276a96807dd45ceed9cbd6fd48b5edf185623b23339a1643e19e8dcbf2e474:0",
            )
            .unwrap(),
        };
        let req = Request::from(msg);
        roundtrip!(req);
        assert_str_ser!(
            req,
            format!("{{\"method\":\"get_spend_tx\",\"params\":{{\"deposit_outpoint\":\"6a276a96807dd45ceed9cbd6fd48b5edf185623b23339a1643e19e8dcbf2e474:0\"}},\"id\":{}}}", req.id()
        ));

        // Response
        let msg = Response {
            result: ResponseResult::SpendTx(coordinator::SpendTx {
                transaction: get_dummy_spend_tx().into_psbt().extract_tx(),
            }),
            id: 0,
        };
        roundtrip!(msg);
        assert_str_ser!(
            msg,
            r#"{"result":{"transaction":"02000000018ef847bc9f2a361ab63f7abe8e56c369d15e730ba89674b09b42674bd40c94f50000000000cd5600000280d8010000000000220020ae1bdee388f2136054797227b14a983d28de29f522f3ebdc4e25fd2bae3d9e5201000000000000000000000000"},"id":0}"#
        );
    }

    #[test]
    fn serde_server_sig() {
        let pubkey = get_dummy_pubkey();
        let signature = get_dummy_sig();
        let id = Txid::default();

        let msg = coordinator::Sig {
            pubkey,
            signature,
            id,
        };
        let req = Request::from(msg);
        roundtrip!(req);
        assert_str_ser!(
            req,
            format!("{{\"method\":\"sig\",\"params\":{{\"pubkey\":\"035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c\",\"signature\":\"3045022100dc4dc264a9fef17a3f253449cf8c397ab6f16fb3d63d86940b5586823dfd02ae02203b461bb4336b5ecbaefd6627aa922efc048fec0c881c10c4c9428fca69c132a2\",\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\"}},\"id\":{}}}", req.id()
        ));

        let resp = Response {
            result: ResponseResult::Sig(coordinator::SigResult { ack: true }),
            id: 0,
        };
        assert_str_ser!(resp, r#"{"result":{"ack":true},"id":0}"#);
        let resp = Response {
            result: ResponseResult::Sig(coordinator::SigResult { ack: false }),
            id: 988364,
        };
        assert_str_ser!(resp, r#"{"result":{"ack":false},"id":988364}"#);
    }

    #[test]
    fn serde_server_get_sigs() {
        let id = Txid::default();
        let msg = coordinator::GetSigs { id };
        let req = Request::from(msg);
        roundtrip!(req);
        assert_str_ser!(
            req,
            format!("{{\"method\":\"get_sigs\",\"params\":{{\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\"}},\"id\":{}}}", req.id()
        ));
    }

    #[test]
    fn serde_server_sigs() {
        let pubkey: PublicKey = get_dummy_pubkey();
        let sig = get_dummy_sig();
        let signatures = [(pubkey, sig)].iter().cloned().collect();

        // With signatures
        let msg = Response {
            result: ResponseResult::Sigs(coordinator::Sigs { signatures }),
            id: 0,
        };
        roundtrip!(msg);
        assert_str_ser!(
            msg,
            r#"{"result":{"signatures":{"035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c":"3045022100dc4dc264a9fef17a3f253449cf8c397ab6f16fb3d63d86940b5586823dfd02ae02203b461bb4336b5ecbaefd6627aa922efc048fec0c881c10c4c9428fca69c132a2"}},"id":0}"#
        );

        // Without signatures
        let signatures = BTreeMap::new();
        let msg = Response {
            result: ResponseResult::Sigs(coordinator::Sigs { signatures }),
            id: 2234,
        };
        roundtrip!(msg);
        assert_str_ser!(msg, r#"{"result":{"signatures":{}},"id":2234}"#);
    }

    #[test]
    fn serde_server_request_spend() {
        let deposit_outpoints = vec![OutPoint::from_str(
            "6e4977728e7100db80c30751f27cf834b7a1e02d083a4338874e48d1f3694446:0",
        )
        .unwrap()];
        let signed_spend_tx = SpendTransaction::from_psbt_str("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").unwrap();
        let msg = coordinator::SetSpendTx::from_spend_tx(deposit_outpoints, signed_spend_tx);
        let req = Request::from(msg);
        roundtrip!(req);
        assert_str_ser!(
            req,
            format!("{{\"method\":\"set_spend_tx\",\"params\":{{\"deposit_outpoints\":[\"6e4977728e7100db80c30751f27cf834b7a1e02d083a4338874e48d1f3694446:0\"],\"transaction\":\"020000000001042a9eb96ed62b3a35883fe632def858e8b80c946ea45f18b364138dfe14dcd70e00000000005ed000003a33ec03af230cf5ae463c2b645f003753bfb06da807b02b89428932cacfaa2301000000005ed000001d9b05aa32106ebb6cf12aefa1115c541b61847aa97823a04be4b77740bfcafc00000000005ed00000e10a83edae847b148100f166ddd65428df8232842df9c26c4ed584313004dc7100000000005ed0000002006f0200000000002200202a3ba224413511e5fc8447c9101d477e2f95db7113ae9fca0b1ef84aac122c605cf6c30000000000000500483045022100a36217e123dea9719dbbc704075dc191f08393537e91ff2630eaf0c7ab89677802207604b290f81148edf8f33c0f84f9aad1391a3513e7a687f721267fc48247adde01473044022055da6db73cf4af14bf8294933dc1b738841c2d6ad371215ceafb61701ac14d9402203626f79d9367ae382041136e52bb378df836b16a97b71c15333bfa3523fbdba701483045022100b2a1b4559bca2719b4abaa7c172329f97b198d5eda2d944d24b684cb42291232022038d74603e78e8e35e02adbe08f93ce90d5d407508463f8e425ddd98abe8fda1701ab2103dacf1ec4d8caaabac45e9237e09d69aadce1b8945dcc4776fe73fb9f4c31f7a4ac51876476a914594f6cd0c51687611968c77d63f40f0422ee26ae88ac6b76a9147ec81e31ce46a8c539882613ee54444fab4fe8a288ac6c93528767522102bf9959bfd4e22513e55bb5905ef3a2a29f9f924adb00c627fd1d92b67ff9cf942102fe9abf103eaa2e1180328774261155380eff416a179e61b0a4be99abcaf88d9b52af035ed000b26805004730440220194744ced4f4637ba2b351bd2562632e93a0e39cc087702514fc2b7fa2da4c0a0220700803ec7e681b1ea31b6463711912dc70bad7bbf50b9f3e063c942a8c1bfe72014730440220216306533836fccc08f07cd8ede702f7ef283539943dc10b93576892ed807217022019bd34f280f74578331377b15cb0f3184d30b2ddb87edd79a0bc63db17aa726b0147304402203a24c13039e1a5abdd8d22dc44036b415b96a4a6cf449145f5bcc89a48cf32af022052c6a253de2c38e41fff9cf16f4869a78e07535ec5806a2ff3f985cb7993fbe201ab2103dacf1ec4d8caaabac45e9237e09d69aadce1b8945dcc4776fe73fb9f4c31f7a4ac51876476a914594f6cd0c51687611968c77d63f40f0422ee26ae88ac6b76a9147ec81e31ce46a8c539882613ee54444fab4fe8a288ac6c93528767522102bf9959bfd4e22513e55bb5905ef3a2a29f9f924adb00c627fd1d92b67ff9cf942102fe9abf103eaa2e1180328774261155380eff416a179e61b0a4be99abcaf88d9b52af035ed000b2680500483045022100bea60c83db41973c639d42cd3525efe82b15456bfba0a904fb77ccb8a8e054cb02206498d4a777c56f943f388eb0f1d765ee8395d1c2e781486d0dd4f0700adc8f0901473044022052ebc8f31d96bd172f2491cd85b0ef9b4aa1f2408e185781cd57a550d7b4f463022069f9e78d039665d5a53c13752d1719e567928c465219a64aa7ee5bc89578b4ad01483045022100b29bf7526aab5fad36f77ecd628352afc12d00c32a0747ad91dd61aae767e4d2022023f0c040ee84caf653d541d8b5f1ac6472e52199056112d99d3a739e57bfaac501ab2103dacf1ec4d8caaabac45e9237e09d69aadce1b8945dcc4776fe73fb9f4c31f7a4ac51876476a914594f6cd0c51687611968c77d63f40f0422ee26ae88ac6b76a9147ec81e31ce46a8c539882613ee54444fab4fe8a288ac6c93528767522102bf9959bfd4e22513e55bb5905ef3a2a29f9f924adb00c627fd1d92b67ff9cf942102fe9abf103eaa2e1180328774261155380eff416a179e61b0a4be99abcaf88d9b52af035ed000b2680500483045022100af1f4b2c3455b044970e8bf62c9e75b4b3e87b5bac7af3b3e33a101e3eebed7202204c377b3764a7dfeccb2f82af327eb23dbf408ae48284a1a7206f43dc04a0b39701483045022100f221ee515d63aef0f27545b736367d0d1ae3ce4433b8818686587decc048b1cc0220536fdfb7470dcd28db813d0efcc2acb364a4d1eece7afcdc9510525993f7487401483045022100faca69e1e8c7b969f0ca666a358693b6bac50b9c02c3722dc2d27a0ccc664563022006ce6039bfcae8a28d74b3d584c37723b466983a4c0ccb63591df74185850a5101ab2103dacf1ec4d8caaabac45e9237e09d69aadce1b8945dcc4776fe73fb9f4c31f7a4ac51876476a914594f6cd0c51687611968c77d63f40f0422ee26ae88ac6b76a9147ec81e31ce46a8c539882613ee54444fab4fe8a288ac6c93528767522102bf9959bfd4e22513e55bb5905ef3a2a29f9f924adb00c627fd1d92b67ff9cf942102fe9abf103eaa2e1180328774261155380eff416a179e61b0a4be99abcaf88d9b52af035ed000b26800000000\"}},\"id\":{}}}", req.id()
        ));

        let response = Response {
            result: ResponseResult::SetSpend(coordinator::SetSpendResult { ack: true }),
            id: 0,
        };
        assert_str_ser!(response, r#"{"result":{"ack":true},"id":0}"#);
        let response = Response {
            result: ResponseResult::SetSpend(coordinator::SetSpendResult { ack: false }),
            id: u32::MAX,
        };
        assert_str_ser!(response, r#"{"result":{"ack":false},"id":4294967295}"#);
    }

    #[test]
    fn serde_cosigner_sign() {
        let tx = get_dummy_spend_tx();
        let msg = cosigner::SignRequest { tx };
        let req = Request::from(msg);
        roundtrip!(req);
        assert_str_ser!(
            req,
            format!("{{\"method\":\"sign\",\"params\":{{\"tx\":\"cHNidP8BAGcCAAAAAY74R7yfKjYatj96vo5Ww2nRXnMLqJZ0sJtCZ0vUDJT1AAAAAADNVgAAAoDYAQAAAAAAIgAgrhve44jyE2BUeXInsUqYPSjeKfUi8+vcTiX9K649nlIBAAAAAAAAAAAAAAAAAAEBK6BK9QUAAAAAIgAgGOT4nZS2eDtYm83Cvrva0Ozxmrw4Wjin73s81+Z/MfEBAwQBAAAAAQX9YgJTIQJXWghCPRbOUhpx+hi93OfpK75maJRYRC38QR4f7+NtFiECM9/45YqHN25XccUBgRIDEcbyVEgt7j61+c9r3RZ7FzohAriewns/EcwKUVDvv1bxr790pkzQRzmqfV3dQ9mzBjaQU65kdqkUqOUtXIDgEzokTmljuXvjUVK6PKqIrGt2qRSxhJ72lPFm92bL1zs0fxxSxgvWIIisbJNrdqkUH5eaO3DdSZU5iyaVBAxs4jQpiiaIrGyTa3apFORRbu2KExrgnCCww5w9TraaoolAiKxsk2t2qRTdO8BPO/zd71a6yb+Cns88TZKG84isbJNrdqkU32Y5t5RL0rYBZZvHWmii6eTcgZ+IrGyTa3apFK83DFJxO+ke61QLvGNyYnmSwKrDiKxsk2t2qRQOTi7K/HfcXcC5iBLjCnMWcMWjIYisbJNYh2dYIQLR/ezgE85uXQeHPU/DkO9OMViCc8qtX1GT1B+pC3O4ASECx3y8Y+ejFiUsobbCiYlAU3h87Q7y+QhADwLFygARZXchAiQAGsW+t/RQ0AJ1axuUM9e58WBlzItzzI4xB8sPnMrsIQKnh96esMFOEyF0tbKBXWmAtff+mxSOoyQVefv/JN/vhSEDiQaTfG58TKdD2N4DbB+wCd3Sz04D4Psle+84rmIW51ghAzFWj+Qs+0gWprDMs3Aat9f5wMZuZaZth1AAtHbe2NbxIQL8522r0lMYLHkL+h2yus2uJP8y6N28+cwpWyaTFNnP+CECdjQgoJBQYwTi7KPMwt1RBcdP0KnnWdYNCSkUmtF972hYrwLOVrJoAAEBaVEhAldaCEI9Fs5SGnH6GL3c5+krvmZolFhELfxBHh/v420WIQIz3/jlioc3bldxxQGBEgMRxvJUSC3uPrX5z2vdFnsXOiECuJ7Cez8RzApRUO+/VvGvv3SmTNBHOap9Xd1D2bMGNpBTrgAA\"}},\"id\":{}}}", req.id()
        ));

        let msg = Response {
            result: ResponseResult::SignResult(cosigner::SignResult { tx: None }),
            id: 975687,
        };
        roundtrip!(msg);
        assert_str_ser!(msg, r#"{"result":{"tx":null},"id":975687}"#);
    }
}
