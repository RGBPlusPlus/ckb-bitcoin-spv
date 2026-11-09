use std::{format, fs::File, io::Read as _, mem};

use bitcoin::{
    absolute::LockTime,
    consensus::serialize,
    hashes::Hash as _,
    merkle_tree::{MerkleBlock, PartialMerkleTree},
    TxMerkleNode,
};
use ckb_bitcoin_spv_verifier::{
    error::VerifyTxError,
    types::{core, packed, prelude::*},
};

use crate::{tests, utilities, BlockProofGenerator, DummyService};

fn assert_invalid_header_proof<T>(result: Result<T, VerifyTxError>) {
    assert_eq!(
        result.map(|_| ()).map_err(|err| err as i8),
        Err(VerifyTxError::HeaderMmrProof as i8),
    );
}

/// Every part of a transaction proof has to hold up on its own.
///
/// Starting from a genuine proof, tampers with one part at a time and expects the
/// header check to catch it.
fn assert_tampered_proofs_are_rejected(
    client: &packed::SpvClient,
    tx_proof: &packed::TransactionProof,
    real_block: &MerkleBlock,
    real_tx: &core::Transaction,
    height: u32,
    max_height: u32,
) {
    // A block that was never mined: the merkle proof is consistent with the made-up
    // header, and the MMR proof is a genuine one for that height.
    {
        let mut tx = real_tx.clone();
        tx.lock_time = LockTime::from_consensus(tx.lock_time.to_consensus_u32() ^ 1);
        let txid = tx.txid();

        let mut header = real_block.header;
        header.merkle_root = TxMerkleNode::from_raw_hash(txid.to_raw_hash());
        let block = MerkleBlock {
            header,
            txn: PartialMerkleTree::from_txids(&[txid], &[true]),
        };
        let forged = tx_proof
            .clone()
            .as_builder()
            .tx_index(0u32.pack())
            .transaction_proof(core::Bytes::from(serialize(&block)).pack())
            .build();

        assert_invalid_header_proof(client.verify_transaction(
            txid.as_ref(),
            forged.as_reader(),
            0,
        ));
        assert_invalid_header_proof(client.verify_transaction_data(
            &serialize(&tx),
            forged.as_reader(),
            0,
        ));
    }

    let real_txid = real_tx.txid();

    // A genuine block with a corrupted MMR proof.
    if let Some(item) = tx_proof.header_proof().get(0) {
        let corrupted = item
            .clone()
            .as_builder()
            .children_hash(core::Hash::hash(item.as_slice()).pack())
            .build();
        let mut items = tx_proof.header_proof().into_iter().collect::<Vec<_>>();
        items[0] = corrupted;
        let forged = tx_proof
            .clone()
            .as_builder()
            .header_proof(packed::MmrProof::new_builder().set(items).build())
            .build();
        assert_invalid_header_proof(client.verify_transaction(
            real_txid.as_ref(),
            forged.as_reader(),
            0,
        ));
    }

    // A genuine block claimed to be at another height.
    if height < max_height {
        let forged = tx_proof
            .clone()
            .as_builder()
            .height((height + 1).pack())
            .build();
        assert_invalid_header_proof(client.verify_transaction(
            real_txid.as_ref(),
            forged.as_reader(),
            0,
        ));
    }
}

fn test_spv_client(
    case_headers: &str,
    case_txoutproofs: &str,
    case_blocks: &str,
    verify_tx_range: (u32, u32),
) {
    tests::setup();

    let headers_path = format!("main-chain/headers/continuous/{case_headers}");
    let txoutproofs_path = format!("main-chain/txoutproof/{case_txoutproofs}");
    let blocks_path = format!("main-chain/blocks/continuous/{case_blocks}");

    // Bootstrap
    let mut header_bins_iter = tests::data::find_bin_files(&headers_path, "").into_iter();
    let mut service = {
        let header_bin = header_bins_iter.next().unwrap();
        let header: core::Header = utilities::decode_from_bin_file(&header_bin).unwrap();
        let height: u32 = header_bin
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        log::trace!("process header-{height} from file {}", header_bin.display());
        let bootstrap = packed::SpvBootstrap::new_builder()
            .height(height.pack())
            .header(header.pack())
            .build();
        let expected_client = bootstrap
            .initialize_spv_client()
            .map_err(|err| err as i8)
            .unwrap()
            .pack();
        let service = DummyService::bootstrap(height, header).unwrap();
        let actual_client: packed::SpvClient = service.tip_client().pack();
        assert_eq!(expected_client.as_slice(), actual_client.as_slice());
        service
    };

    // Update
    let mut old_client: packed::SpvClient = service.tip_client().pack();
    let mut headers = Vec::new();
    let mut headers_group_size = 1;
    for header_bin in header_bins_iter {
        let header: core::Header = utilities::decode_from_bin_file(&header_bin).unwrap();
        let height: u32 = header_bin
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        log::trace!("process header-{height} from file {}", header_bin.display());

        headers.push(header);
        if height + 1 != verify_tx_range.0 && headers.len() < headers_group_size {
            continue;
        }

        log::trace!("process {} headers at one time", headers.len());
        let update = if headers_group_size % 5 == 0 {
            let tmp_headers = mem::take(&mut headers);
            let _update = service.update(tmp_headers.clone()).unwrap();
            log::trace!("rollback to previous client (for test): {old_client}");
            service.rollback_to(old_client.unpack()).unwrap();
            log::trace!("process {} headers again", headers.len());
            service.update(tmp_headers)
        } else {
            service.update(mem::take(&mut headers))
        }
        .unwrap();
        if verify_tx_range.0 <= height + 1 && height <= verify_tx_range.1 {
            headers_group_size = 1;
        } else {
            headers_group_size += 1;
        }
        let new_client: packed::SpvClient = service.tip_client().pack();

        old_client
            .verify_new_client(&new_client, update, 0)
            .map_err(|err| err as i8)
            .unwrap();
        old_client = new_client;

        // Verify Tx in different heights
        if verify_tx_range.0 <= height && height <= verify_tx_range.1 {
            let tip_client: packed::SpvClient = service.tip_client().pack();
            let max_height = service.max_height();

            for bin_file in tests::data::find_bin_files(&txoutproofs_path, "") {
                log::trace!("process txoutproof from file {}", bin_file.display());

                let actual = File::open(&bin_file)
                    .and_then(|mut file| {
                        let mut data = Vec::new();
                        file.read_to_end(&mut data).map(|_| data)
                    })
                    .unwrap();
                let real_block: core::MerkleBlock =
                    utilities::decode_from_slice(&actual).expect("check binary data");

                let file_stem = bin_file.file_stem().unwrap().to_str().unwrap();
                let (height, tx_index) =
                    if let Some((height_str, indexes_str)) = file_stem.split_once('-') {
                        let height: u32 = height_str.parse().unwrap();
                        let indexes = indexes_str
                            .split('_')
                            .filter(|s| !s.is_empty())
                            .map(|s| {
                                s.parse()
                                    .map_err(|err| format!("failed to parse \"{s}\" since {err}"))
                            })
                            .collect::<Result<Vec<u32>, _>>()
                            .unwrap();
                        if indexes.len() > 1 {
                            log::warn!("TODO with current APIs, only ONE tx is allowed each time");
                            continue;
                        }
                        (height, indexes[0])
                    } else {
                        panic!("invalid txoutproof file stem \"{file_stem}\"");
                    };

                let header_proof = service
                    .generate_header_proof(height)
                    .unwrap()
                    .unwrap_or_default();
                let tx_proof = packed::TransactionProof::new_builder()
                    .tx_index(tx_index.pack())
                    .height(height.pack())
                    .transaction_proof(core::Bytes::from(actual).pack())
                    .header_proof(header_proof.pack())
                    .build();

                let block_filename = format!("{height:07}.bin");
                let block_file = tests::data::find_bin_file(&blocks_path, &block_filename);
                let bpg = BlockProofGenerator::from_bin_file(&block_file).unwrap();
                let tx = bpg.get_transaction(tx_index as usize).unwrap();
                let txid = tx.txid();
                let tx_bytes = serialize(tx);

                log::debug!("client-tip {max_height}, tx-height {height}, no confirmations");

                let verify_result = tip_client
                    .verify_transaction_data(&tx_bytes, tx_proof.as_reader(), 0)
                    .map_err(|err| err as i8);
                if height <= max_height {
                    assert!(verify_result.is_ok());
                    assert_tampered_proofs_are_rejected(
                        &tip_client,
                        &tx_proof,
                        &real_block,
                        tx,
                        height,
                        max_height,
                    );
                } else {
                    assert!(verify_result.is_err());
                }

                if height + 2 > max_height {
                    continue;
                }

                let confirmations = max_height - height;

                log::debug!(">>> with confirmations {confirmations}");

                let txid_array = txid.as_ref();
                let verify_result = tip_client
                    .verify_transaction(txid_array, tx_proof.as_reader(), confirmations - 1)
                    .map_err(|err| err as i8);
                assert!(verify_result.is_ok());
                let verify_result = tip_client
                    .verify_transaction(txid_array, tx_proof.as_reader(), confirmations)
                    .map_err(|err| err as i8);
                assert!(verify_result.is_ok());
                let verify_result = tip_client
                    .verify_transaction(txid_array, tx_proof.as_reader(), confirmations + 1)
                    .map_err(|err| err as i8);
                assert!(verify_result.is_err());
            }
        }
    }
}

#[test]
fn spv_client_case_1() {
    test_spv_client(
        "case-0822528_0830592",
        "case-0830000",
        "case-0830000_0830000",
        (829995, 830005),
    );
}
