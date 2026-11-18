//! Offline state-transition regressions. Mainnet boundary headers come from the
//! pinned test-data submodule; synthetic easy-target cases test verifier rules,
//! not Bitcoin network admission or a complete on-chain reorganization.
use bitcoin::{blockdata::constants::genesis_block, Network};
use ckb_bitcoin_spv_verifier::{
    constants::{FLAG_CHAIN_TYPE_SIGNET, FLAG_CHAIN_TYPE_TESTNET},
    error::UpdateError,
    types::{core, packed, prelude::*},
    utilities::mmr::{lib::util::MemStore, ClientRootMMR},
};
use std::{fs, path::PathBuf};

fn header_at(height: u32) -> core::Header {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/data/main-chain/headers/continuous/case-0822528_0830592")
        .join(format!("{height:07}.bin"));
    bitcoin::consensus::deserialize(
        &fs::read(path).expect("initialize the pinned tests/data submodule"),
    )
    .unwrap()
}

fn client(
    root: packed::HeaderDigest,
    tip: &core::Header,
    info: packed::TargetAdjustInfo,
) -> packed::SpvClient {
    packed::SpvClient::new_builder()
        .id(7u8.into())
        .headers_mmr_root(root)
        .tip_block_hash(core::Hash::from(tip.block_hash()).pack())
        .target_adjust_info(info)
        .build()
}

fn transition(
    old_headers: &[(u32, core::Header)],
    added: &[core::Header],
    old_info: packed::TargetAdjustInfo,
    new_info: packed::TargetAdjustInfo,
) -> (packed::SpvClient, packed::SpvClient, packed::SpvUpdate) {
    let store = MemStore::default();
    let mut mmr = ClientRootMMR::new(0, &store);
    for (height, header) in old_headers {
        mmr.push(core::HeaderDigest::new_leaf(*height, header).pack())
            .unwrap();
    }
    mmr.commit().unwrap();
    let (last_height, last_header) = old_headers.last().unwrap();
    let old = client(mmr.get_root().unwrap(), last_header, old_info);
    let mut positions = Vec::new();
    for (offset, header) in added.iter().enumerate() {
        positions.push(
            mmr.push(core::HeaderDigest::new_leaf(last_height + offset as u32 + 1, header).pack())
                .unwrap(),
        );
    }
    mmr.commit().unwrap();
    let proof = mmr.gen_proof(positions).unwrap();
    let new = client(mmr.get_root().unwrap(), added.last().unwrap(), new_info);
    let update = packed::SpvUpdate::new_builder()
        .headers(added.to_vec().pack())
        .new_headers_mmr_proof(
            packed::MmrProof::new_builder()
                .set(proof.proof_items().to_vec())
                .build(),
        )
        .build();
    (old, new, update)
}
fn verify(
    old: &packed::SpvClient,
    new: &packed::SpvClient,
    update: &packed::SpvUpdate,
    flags: u8,
) -> Result<(), i8> {
    old.verify_new_client(new, update.clone(), flags)
        .map_err(|e| e as i8)
}

#[test]
fn mainnet_period_boundary_updates_target_then_period_start_in_single_steps() {
    // 824544 = 409 * 2016. Independent expected bits/time are read from
    // adjacent historical headers, not calculated by the function under test.
    let period_start = header_at(822528);
    let last = header_at(824543);
    let first = header_at(824544);
    let second = header_at(824545);
    assert_ne!(
        last.bits, first.bits,
        "fixture must exercise an actual retarget"
    );
    let before = packed::TargetAdjustInfo::encode(period_start.time, last.bits);
    let adjusted = packed::TargetAdjustInfo::encode(period_start.time, first.bits);
    let restarted = packed::TargetAdjustInfo::encode(first.time, first.bits);
    let mut current_info = before;
    for (height, header, expected) in [
        (824543, last, adjusted),
        (824544, first, restarted.clone()),
        (824545, second, restarted),
    ] {
        let (old, new, update) = transition(
            &[(height - 1, header_at(height - 1))],
            &[header],
            current_info.clone(),
            expected.clone(),
        );
        assert_eq!(verify(&old, &new, &update, 0), Ok(()));
        if current_info.as_slice() != expected.as_slice() {
            let stale = new.as_builder().target_adjust_info(current_info).build();
            assert_eq!(
                verify(&old, &stale, &update, 0),
                Err(UpdateError::ClientTargetAdjustInfo as i8)
            );
        }
        current_info = expected;
    }
}

#[test]
fn mainnet_multi_peak_append_crosses_retarget_boundary_and_binds_old_history() {
    let old_headers: Vec<_> = (824540..=824542).map(|h| (h, header_at(h))).collect(); // 3 leaves / 2 peaks
    let added: Vec<_> = (824543..=824545).map(header_at).collect();
    let before = packed::TargetAdjustInfo::encode(header_at(822528).time, header_at(824542).bits);
    let after = packed::TargetAdjustInfo::encode(header_at(824544).time, header_at(824544).bits);
    let (old, new, update) = transition(&old_headers, &added, before, after);
    assert_eq!(verify(&old, &new, &update, 0), Ok(()));
    let mut changed: core::SpvClient = old.unpack();
    changed.headers_mmr_root.children_hash = core::Hash::from_byte_array([0x42; 32]);
    assert_eq!(
        verify(&changed.pack(), &new, &update, 0),
        Err(UpdateError::HeadersMmrProof as i8)
    );
    let missing = update
        .as_builder()
        .new_headers_mmr_proof(packed::MmrProof::default())
        .build();
    assert_eq!(verify(&old, &new, &missing, 0), Err(UpdateError::Mmr as i8));
}

fn mine(mut header: core::Header) -> core::Header {
    for nonce in 0..10000 {
        header.nonce = nonce;
        if header.validate_pow(header.target()).is_ok() {
            return header;
        }
    }
    panic!("bounded easy-target fixture search failed");
}

#[test]
fn target_equality_exception_is_testnet_only_and_does_not_bypass_pow() {
    let old_header = genesis_block(Network::Regtest).header;
    let mut next = old_header;
    next.prev_blockhash = old_header.block_hash();
    next.time += 1;
    next.bits = core::CompactTarget::from_consensus(0x207ffffe);
    let next = mine(next);
    let info = packed::TargetAdjustInfo::encode(old_header.time, old_header.bits);
    let (old, new, update) = transition(&[(10, old_header)], &[next], info.clone(), info);
    // This tests the implementation's flag-controlled equality exception. It
    // does not claim full Bitcoin testnet difficulty/elapsed-time consensus.
    assert_eq!(verify(&old, &new, &update, FLAG_CHAIN_TYPE_TESTNET), Ok(()));
    for flags in [0, FLAG_CHAIN_TYPE_SIGNET] {
        assert_eq!(
            verify(&old, &new, &update, flags),
            Err(UpdateError::Difficulty as i8)
        );
    }
    let mut invalid = next;
    invalid.nonce = (0..10000)
        .find(|nonce| {
            invalid.nonce = *nonce;
            invalid.validate_pow(invalid.target()).is_err()
        })
        .unwrap();
    let update = update.as_builder().headers(vec![invalid].pack()).build();
    assert_eq!(
        verify(&old, &new, &update, FLAG_CHAIN_TYPE_TESTNET),
        Err(UpdateError::Pow as i8)
    );
}

#[test]
fn incremental_mmr_appends_from_multiple_existing_peak_shapes() {
    for old_count in [3u32, 5, 7] {
        for added_count in [1u32, 2, 4, 8] {
            let start = 824500;
            let old_headers: Vec<_> = (start..start + old_count)
                .map(|h| (h, header_at(h)))
                .collect();
            let added: Vec<_> = (start + old_count..start + old_count + added_count)
                .map(header_at)
                .collect();
            let info =
                packed::TargetAdjustInfo::encode(header_at(822528).time, header_at(start).bits);
            let (old, new, update) = transition(&old_headers, &added, info.clone(), info);
            assert_eq!(
                verify(&old, &new, &update, 0),
                Ok(()),
                "old={old_count}, append={added_count}"
            );
            assert_eq!(new.headers_mmr_root().min_height().unpack(), start);
            assert_eq!(
                new.headers_mmr_root().max_height().unpack(),
                start + old_count + added_count - 1
            );
            assert!(new.is_better_than(&old));
            // The same append must not validate if the retained history's work
            // was changed, even though tip and height still agree.
            let mut tampered: core::SpvClient = old.unpack();
            tampered.headers_mmr_root.partial_chain_work += core::U256::one();
            assert_eq!(
                verify(&tampered.pack(), &new, &update, 0),
                Err(UpdateError::HeadersMmrProof as i8)
            );
        }
    }
}

#[test]
fn historical_signet_period_end_rejects_mainnet_clamp_and_accepts_signet_state() {
    use ckb_jsonrpc_types::TransactionView;
    use ckb_types::{packed::WitnessArgs, prelude::*};
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/data/signet");
    let tx: TransactionView = serde_json::from_slice(
        &fs::read(
            root.join("tx-0xd663a1dfdfbf9a4824950c44c0d5f5e65f6b1ba4710a0308edecadeaed3ac549.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let witness = WitnessArgs::from_slice(tx.inner.witnesses[0].as_bytes()).unwrap();
    let update =
        packed::SpvUpdate::from_slice(&witness.output_type().to_opt().unwrap().raw_data()).unwrap();
    let new = packed::SpvClient::from_slice(tx.inner.outputs_data[1].as_bytes()).unwrap();
    let point = &tx.inner.cell_deps[2].out_point;
    let previous: TransactionView = serde_json::from_slice(
        &fs::read(root.join(format!("tx-0x{}.json", point.tx_hash))).unwrap(),
    )
    .unwrap();
    let old = packed::SpvClient::from_slice(
        previous.inner.outputs_data[point.index.value() as usize].as_bytes(),
    )
    .unwrap()
    .as_builder()
    .id(new.id())
    .build();
    assert_eq!(new.headers_mmr_root().max_height().unpack(), 197567u32);
    assert_eq!(
        new.target_adjust_info().decode().unwrap().1.to_consensus(),
        0x1d00ffff
    );
    assert_eq!(
        verify(&old, &new, &update, FLAG_CHAIN_TYPE_SIGNET),
        Err(UpdateError::ClientTargetAdjustInfo as i8)
    );
    // Independent expected bits from the next historical signet period, not
    // calculate_next_target. Reference: target_adjust_info in the pinned
    // tx-0528-error-check-header-target-adjust-info.json (height 197577).
    // The fixture's old result incorrectly used the
    // much smaller mainnet target cap.
    let start = old.target_adjust_info().decode().unwrap().0;
    let corrected = new
        .as_builder()
        .target_adjust_info(packed::TargetAdjustInfo::encode(
            start,
            core::CompactTarget::from_consensus(0x1e0149b6),
        ))
        .build();
    assert_eq!(
        verify(&old, &corrected, &update, FLAG_CHAIN_TYPE_SIGNET),
        Ok(())
    );
}
