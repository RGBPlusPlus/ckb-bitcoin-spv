//! Offline membership tests using synthetic blocks and trusted client roots.
//! They run the real verifier, but do not establish PoW chain admission, script
//! validity, or SegWit witness-commitment validation (the API proves txid inclusion).
use bitcoin::{blockdata::constants::genesis_block, consensus::serialize, Network, Witness};
use ckb_bitcoin_spv_verifier::{
    error::VerifyTxError,
    types::{core, packed, prelude::*},
    utilities::mmr::{lib::util::MemStore, ClientRootMMR},
};

const START: u32 = 100;

fn transaction(witness: bool) -> core::Transaction {
    let mut tx = genesis_block(Network::Bitcoin).txdata.remove(0);
    if witness {
        tx.input[0].witness = Witness::from_slice(&[vec![1, 2, 3], vec![4, 5]]);
    }
    tx
}

fn fixture(
    count: usize,
    selected: usize,
    tx: &core::Transaction,
) -> (packed::SpvClient, packed::TransactionProof, core::Header) {
    assert!(selected < count);
    let store = MemStore::default();
    let mut mmr = ClientRootMMR::new(0, &store);
    let mut selected_block = None;
    let mut selected_pos = 0;
    let mut tip = genesis_block(Network::Bitcoin).header;
    for index in 0..count {
        let mut block = genesis_block(Network::Bitcoin);
        block.txdata = vec![tx.clone()];
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        block.header.time += index as u32;
        block.header.nonce = index as u32;
        if index != 0 {
            block.header.prev_blockhash = tip.block_hash();
        }
        tip = block.header;
        let pos = mmr
            .push(core::HeaderDigest::new_leaf(START + index as u32, &block.header).pack())
            .unwrap();
        if index == selected {
            selected_pos = pos;
            selected_block = Some(block);
        }
    }
    mmr.commit().unwrap();
    let block = selected_block.unwrap();
    let merkle = core::MerkleBlock::from_block_with_predicate(&block, |_| true);
    let path = mmr.gen_proof(vec![selected_pos]).unwrap();
    let client = packed::SpvClient::new_builder()
        .headers_mmr_root(mmr.get_root().unwrap())
        .tip_block_hash(core::Hash::from(tip.block_hash()).pack())
        .build();
    let proof = packed::TransactionProof::new_builder()
        .height((START + selected as u32).pack())
        .tx_index(0u32.pack())
        .transaction_proof(core::Bytes::from(serialize(&merkle)).pack())
        .header_proof(
            packed::MmrProof::new_builder()
                .set(path.proof_items().to_vec())
                .build(),
        )
        .build();
    (client, proof, block.header)
}

fn verify(
    client: &packed::SpvClient,
    proof: &packed::TransactionProof,
    tx: &core::Transaction,
    confirmations: u32,
) -> Result<core::Header, i8> {
    client
        .verify_transaction_data(&serialize(tx), proof.as_reader(), confirmations)
        .map(|(header, decoded)| {
            assert_eq!(&decoded, tx);
            header
        })
        .map_err(|e| e as i8)
}

#[test]
fn segwit_data_uses_txid_not_wtxid_for_membership() {
    let tx = transaction(true);
    let (client, proof, header) = fixture(7, 4, &tx);
    let txid_hash = tx.txid();
    let wtxid_hash = tx.wtxid();
    let txid: &[u8; 32] = txid_hash.as_ref();
    let wtxid: &[u8; 32] = wtxid_hash.as_ref();
    assert_ne!(txid, wtxid);
    assert_eq!(verify(&client, &proof, &tx, 2), Ok(header));
    assert!(matches!(
        client.verify_transaction(wtxid, proof.as_reader(), 2),
        Err(VerifyTxError::TxOutProofInvalidTxId)
    ));
}

#[test]
fn witness_only_changes_do_not_authenticate_witness_contents() {
    let tx = transaction(true);
    let (client, proof, header) = fixture(3, 1, &tx);
    let mut changed = tx.clone();
    changed.input[0].witness = Witness::from_slice(&[vec![9, 8, 7]]);
    assert_eq!(tx.txid(), changed.txid());
    assert_ne!(tx.wtxid(), changed.wtxid());
    // This acceptance is intentional: a txid Merkle proof does not prove witness data.
    assert_eq!(verify(&client, &proof, &changed, 1), Ok(header));
    changed.output[0].value = bitcoin::Amount::from_sat(1);
    assert_ne!(tx.txid(), changed.txid());
    assert_eq!(
        verify(&client, &proof, &changed, 1),
        Err(VerifyTxError::TxOutProofInvalidTxId as i8)
    );
}

#[test]
fn all_leaf_positions_across_single_and_multiple_peak_mmrs_verify() {
    let tx = transaction(false);
    // Includes perfect trees, multi-peak trees, and transitions across powers of two.
    for count in [1usize, 2, 3, 4, 5, 7, 8, 9] {
        for selected in 0..count {
            let (client, proof, header) = fixture(count, selected, &tx);
            let depth = (count - selected - 1) as u32;
            assert_eq!(
                verify(&client, &proof, &tx, depth),
                Ok(header),
                "count={count}, selected={selected}"
            );
            assert_eq!(
                verify(&client, &proof, &tx, depth + 1),
                Err(VerifyTxError::TransactionUnconfirmed as i8),
                "count={count}, selected={selected}"
            );
        }
    }
}

#[test]
fn altered_missing_extra_and_reordered_mmr_nodes_are_rejected() {
    let tx = transaction(false);
    let (client, proof, header) = fixture(7, 0, &tx);
    assert_eq!(verify(&client, &proof, &tx, 0), Ok(header));
    let nodes: Vec<_> = proof.header_proof().into_iter().collect();
    assert!(nodes.len() >= 2);
    let mut altered = nodes.clone();
    altered[0] = altered[0]
        .clone()
        .as_builder()
        .children_hash(core::Hash::from_byte_array([0x42; 32]).pack())
        .build();
    let mut missing = nodes.clone();
    missing.pop();
    let mut extra = nodes.clone();
    extra.push(nodes[0].clone());
    let mut reordered = nodes;
    reordered.swap(0, 1);
    for changed in [altered, missing, extra, reordered] {
        let changed = proof
            .clone()
            .as_builder()
            .header_proof(packed::MmrProof::new_builder().set(changed).build())
            .build();
        assert_eq!(
            verify(&client, &changed, &tx, 0),
            Err(VerifyTxError::HeaderMmrProof as i8)
        );
    }
}

#[test]
fn in_range_but_wrong_height_cannot_reuse_a_header_proof() {
    let tx = transaction(false);
    let (client, proof, header) = fixture(7, 2, &tx);
    assert_eq!(verify(&client, &proof, &tx, 0), Ok(header));
    for height in [START, START + 1, START + 3, START + 6] {
        let changed = proof.clone().as_builder().height(height.pack()).build();
        assert_eq!(
            verify(&client, &changed, &tx, 0),
            Err(VerifyTxError::HeaderMmrProof as i8)
        );
    }
}
