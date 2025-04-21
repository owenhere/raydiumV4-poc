use anyhow::{format_err, Result};
use safe_transmute::{
    to_bytes::{transmute_one_to_bytes, transmute_to_bytes},
    transmute_many_pedantic, transmute_one_pedantic,
};
use serum_dex::state::{gen_vault_signer_key, AccountFlag, Market, MarketState, MarketStateV2};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::{borrow::Cow, convert::TryFrom};

#[derive(Clone, Debug)]
pub struct MarketPubkeys {
    pub market: Pubkey,
    pub req_q: Pubkey,
    pub event_q: Pubkey,
    pub bids: Pubkey,
    pub asks: Pubkey,
    pub coin_vault: Pubkey,
    pub pc_vault: Pubkey,
    pub vault_signer_key: Pubkey,
    pub coin_mint: Pubkey,
    pub pc_mint: Pubkey,
    pub coin_lot_size: u64,
    pub pc_lot_size: u64,
}

fn remove_dex_account_padding(data: &[u8]) -> Result<Cow<[u64]>> {
    use serum_dex::state::{ACCOUNT_HEAD_PADDING, ACCOUNT_TAIL_PADDING};

    if data.len() < ACCOUNT_HEAD_PADDING.len() + ACCOUNT_TAIL_PADDING.len() {
        return Err(format_err!(
            "dex account length {} is too small to contain valid padding",
            data.len()
        ));
    }

    if &data[..ACCOUNT_HEAD_PADDING.len()] != ACCOUNT_HEAD_PADDING {
        return Err(format_err!("dex account head padding mismatch"));
    }

    if &data[data.len() - ACCOUNT_TAIL_PADDING.len()..] != ACCOUNT_TAIL_PADDING {
        return Err(format_err!("dex account tail padding mismatch"));
    }

    let inner_data = &data[ACCOUNT_HEAD_PADDING.len()..(data.len() - ACCOUNT_TAIL_PADDING.len())];

    match transmute_many_pedantic::<u64>(inner_data) {
        Ok(word_slice) => Ok(Cow::Borrowed(word_slice)),
        Err(e) => {
            let word_vec = e.copy().map_err(|e| e.without_src())?;
            Ok(Cow::Owned(word_vec))
        }
    }
}

pub fn get_keys_for_market(
    client: &RpcClient,
    market_key: &Pubkey,
    market: &Pubkey,
) -> Result<MarketPubkeys> {
    let account_data = client.get_account_data(market)?;
    let words = remove_dex_account_padding(&account_data)?;

    let market_state: MarketState = {
        let account_flags = Market::account_flags(&account_data)?;

        if account_flags.intersects(AccountFlag::Permissioned) {
            println!("MarketStateV2");
            let state = transmute_one_pedantic::<MarketStateV2>(transmute_to_bytes(&words))
                .map_err(|e| e.without_src())?;
            state.check_flags(true)?;
            state.inner
        } else {
            let state = transmute_one_pedantic::<MarketState>(transmute_to_bytes(&words))
                .map_err(|e| e.without_src())?;
            state.check_flags(true)?;
            state
        }
    };

    // Validate market address matches
    if market_state.own_address.as_ref() != market.as_ref() {
        return Err(format_err!("Market address mismatch in account data"));
    }

    let vault_signer_key = gen_vault_signer_key(market_state.vault_signer_nonce, market, market_key)?;

    // Convert all pubkeys safely, propagate errors
    let convert_pubkey = |bytes: &[u8]| -> Result<Pubkey> {
        Pubkey::try_from(bytes).map_err(|_| format_err!("Invalid pubkey bytes"))
    };

    Ok(MarketPubkeys {
        market: *market,
        req_q: convert_pubkey(transmute_one_to_bytes(&market_state.req_q))?,
        event_q: convert_pubkey(transmute_one_to_bytes(&market_state.event_q))?,
        bids: convert_pubkey(transmute_one_to_bytes(&market_state.bids))?,
        asks: convert_pubkey(transmute_one_to_bytes(&market_state.asks))?,
        coin_vault: convert_pubkey(transmute_one_to_bytes(&market_state.coin_vault))?,
        pc_vault: convert_pubkey(transmute_one_to_bytes(&market_state.pc_vault))?,
        vault_signer_key,
        coin_mint: convert_pubkey(transmute_one_to_bytes(&market_state.coin_mint))?,
        pc_mint: convert_pubkey(transmute_one_to_bytes(&market_state.pc_mint))?,
        coin_lot_size: market_state.coin_lot_size,
        pc_lot_size: market_state.pc_lot_size,
    })
}
