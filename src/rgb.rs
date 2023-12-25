use bpstd::{Tx, Txid};
use rgbstd::resolvers::ResolveHeight;
use rgbstd::validation::{ResolveTx, TxResolverError};
use rgbstd::{Layer1, WitnessAnchor, WitnessId, WitnessOrd, WitnessPos, XAnchor};

use crate::{BlockingClient, Error};

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ResolverError {
    #[from]
    #[display(inner)]
    Error(Error),

    /// invalid anchor {0}
    InvalidAnchor(String),
}

impl ResolveHeight for BlockingClient {
    type Error = ResolverError;

    fn resolve_anchor(&mut self, anchor: &XAnchor) -> Result<WitnessAnchor, Self::Error> {
        let XAnchor::Bitcoin(anchor) = anchor else {
            panic!("Liquid is not yet supported")
        };
        let txid = anchor
            .txid()
            .ok_or(ResolverError::InvalidAnchor(format!("{:#?}", anchor)))?;
        let status = self.tx_status(&txid)?;
        let ord = match status
            .block_height
            .and_then(|h| status.block_time.map(|t| (h, t)))
        {
            Some((h, t)) => {
                WitnessOrd::OnChain(WitnessPos::new(h, t as i64).ok_or(Error::InvalidServerData)?)
            }
            None => WitnessOrd::OffChain,
        };
        Ok(WitnessAnchor {
            witness_ord: ord,
            witness_id: WitnessId::Bitcoin(txid),
        })
    }
}

impl ResolveTx for BlockingClient {
    fn resolve_bp_tx(&self, layer1: Layer1, txid: Txid) -> Result<Tx, TxResolverError> {
        assert_eq!(layer1, Layer1::Bitcoin, "Liquid is not yet supported");
        self.tx(&txid)
            .map_err(|err| TxResolverError::Other(txid, err.to_string()))?
            .ok_or(TxResolverError::Unknown(txid))
    }
}
