#![feature(trim_prefix_suffix)]
use alloy_consensus::transaction::Transaction;
use alloy_primitives::{Address, U256};
use alloy_provider::Provider;
use alloy_provider::{RootProvider, network::Ethereum};
use anyhow::Context;
use bitcoin_light_client_circuit::EthClientExecutorInput;
use cbft_rpc::{
    HttpClient, fetch_cbft_tx_data, fetch_cbft_validator_info, fetch_cosmos_block,
    get_cosmos_block_height_at,
};
use futures_util::{StreamExt, TryStreamExt, stream};
use host_executor::EthHostExecutor;
use primitives::genesis::Genesis;
use proof_builder::ProofRequest;
use proof_builder::{LongRunning, ProofBuilder};
use reth_chainspec::ChainSpec;
use state_chain::*;
use std::sync::Arc;
use url::Url;
use zkm_sdk::{
    HashableKey, ProverClient, ZKM_CIRCUIT_VERSION, ZKMProofKind, ZKMProofWithPublicValues,
    ZKMStdin, include_elf,
};

use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use util::hex_parse;
static ELF_ID: OnceLock<String> = OnceLock::new();

/// A program that aggregates the proofs of the simple program.
pub const STATE_CHAIN: &[u8] = include_elf!("state-chain-guest");

use std::fs;

use clap::Parser;

/// The arguments for the cli.
#[derive(Debug, Clone, Parser, serde::Deserialize, serde::Serialize)]
pub struct Args {
    #[arg(long, default_value_t = false)]
    #[serde(default)]
    pub print_program_id: bool,

    #[arg(long, default_value_t = true)]
    pub enable: bool,

    #[clap(long, env, short, default_value = "https://rpc.testnet3.goat.network")]
    pub execution_layer_rpc: String,

    #[clap(long, env, default_value = "goattest")]
    pub goat_network: String,

    #[clap(long, env, default_value = "https://rpc.testnet3.goat.network/goat-rpc")]
    pub cosmos_rpc_url: String,

    #[arg(long, default_value = "blocks.bin")]
    pub blocks: String,

    #[clap(long, env, default_value_t = false)]
    pub init_input: bool,

    #[clap(long, env, default_value = "input.bin")]
    pub input_proof: String,

    #[clap(long, env, default_value = "output.bin")]
    pub output_proof: String,

    #[clap(long, env, default_value_t = 10)]
    pub batch_size: u64,

    #[clap(long, env, default_value_t = 0)]
    pub start: u64,

    /// GOAT blocks fetched at once. Each block takes ~13 sequential RPC round trips.
    #[clap(long, env, default_value_t = default_fetch_concurrency())]
    #[serde(default = "default_fetch_concurrency")]
    pub fetch_concurrency: usize,

    // Print-only mode skips runtime inputs but keeps them required otherwise.
    #[clap(
        long,
        env,
        required = false,
        required_unless_present = "print_program_id",
        default_value_if("print_program_id", "true", Some(""))
    )]
    pub l2_contract_addresses: String,

    // https://explorer.testnet3.goat.network/address/0x9F0A61ce47678F43A326dB9F8964C56a924cd3D0?tab=read_write_contract
    #[clap(
        long,
        env,
        required = false,
        required_unless_present = "print_program_id",
        default_value_if("print_program_id", "true", Some(""))
    )]
    pub proceed_withdraw_method_ids: String,
}

fn default_fetch_concurrency() -> usize {
    16
}

impl LongRunning for Args {
    fn rotate(&self) -> Self {
        let mut next_args = self.clone();
        next_args.input_proof = self.output_proof.clone();
        next_args.init_input = false;
        next_args.start = self.start + self.batch_size;
        next_args.output_proof = format!(
            "{}/{}-{}.bin",
            std::path::Path::new(&self.output_proof).parent().unwrap().to_str().unwrap(),
            next_args.start,
            self.batch_size
        );
        next_args.blocks = format!("{}.blocks", next_args.input_proof);
        next_args
    }
}

/// The proceed-withdraw calls in GOAT block `number`, as (graph id, contract), in transaction order.
async fn fetch_withdrawal_events(
    provider: &RootProvider<Ethereum>,
    l2_contract_addresses: &[Address],
    proceed_withdraw_method_ids: &[[u8; 4]],
    number: u64,
) -> Vec<([u8; 16], Address)> {
    let mut withdrawals = vec![];
    let block = match provider.get_block(number.into()).await {
        Ok(Some(x)) => x,
        Ok(None) => {
            tracing::error!("get block {number} returns none");
            return withdrawals;
        }
        Err(e) => {
            tracing::error!("get block {number} error, {e}");
            return withdrawals;
        }
    };
    for txid in block.transactions.hashes() {
        let txn = match provider.get_transaction_by_hash(txid).await {
            Ok(Some(x)) => x,
            Ok(None) => {
                tracing::error!("get transaction by hash {txid} returns none");
                continue;
            }
            Err(e) => {
                tracing::error!("get transaction by hash {txid} error, {e}");
                continue;
            }
        };
        let to = txn.to();
        let input = txn.input();
        l2_contract_addresses.iter().zip(proceed_withdraw_method_ids.iter()).for_each(
            |(l2_contract_address, proceed_withdraw_method_id)| {
                if to == Some(*l2_contract_address) && &input[0..4] == proceed_withdraw_method_id {
                    let graph_id: [u8; 16] = input[4..16 + 4].try_into().unwrap();
                    withdrawals.push((graph_id, *l2_contract_address));
                    println!("block: {number}, graph_id: {:?}", hex::encode(graph_id));
                }
            },
        );
    }
    withdrawals
}

// https://github.com/ProjectZKM/reth-processor/blob/stateless/crates/executor/host/tests/integration.rs#L69
async fn fetch_exection_layer_block(
    provider: &RootProvider<Ethereum>,
    execution_layer_block_number: u64,
    genesis: &Genesis,
) -> anyhow::Result<EthClientExecutorInput> {
    //let rpc_db = RpcDb::new(provider.clone(), provider.clone(), execution_layer_block_number - 1);
    let chain_spec: Arc<ChainSpec> = Arc::new(genesis.try_into().unwrap());
    let custom_beneficiary = None;
    let host_executor = EthHostExecutor::eth(chain_spec, custom_beneficiary);
    // Execute the host.
    let client_input = host_executor
        .execute(
            execution_layer_block_number,
            provider,
            provider,
            genesis.clone(),
            custom_beneficiary,
            false,
        )
        .await?;
    Ok(client_input)
}

/// Everything the circuit needs from GOAT block `i`. The block's requests run one after another;
/// a failure asks the caller to retry the batch after `retry_after` seconds.
#[allow(clippy::too_many_arguments)]
async fn fetch_state_block(
    provider: &RootProvider<Ethereum>,
    cosmos: &HttpClient,
    genesis: &Genesis,
    l2_contract_addresses: &[Address],
    proceed_withdraw_method_ids: &[[u8; 4]],
    base_slot: [u8; 32],
    i: u64,
    retry_after: u64,
) -> anyhow::Result<CircuitStateBlock> {
    // fetch graph_ids proceeded in goat block i
    let withdrawal_events =
        fetch_withdrawal_events(provider, l2_contract_addresses, proceed_withdraw_method_ids, i)
            .await;

    let evm_block = fetch_exection_layer_block(provider, i, genesis).await.map_err(|e| {
        tracing::error!("fetch_exection_layer_block: {e:?}");
        proof_builder::ProofError::InputNotReady(retry_after)
    })?;

    let parent_beacon_block_root = evm_block.current_block.header.parent_beacon_block_root.unwrap();

    let parent_cosmos_block_height =
        get_cosmos_block_height_at(cosmos, *parent_beacon_block_root).await.unwrap_or_default();

    let (_, cl_block_number) =
        fetch_cbft_validator_info(cosmos, i, parent_cosmos_block_height, 1000).await.map_err(
            |e| {
                tracing::error!("fetch_cbft_validator_info: {e:?}");
                proof_builder::ProofError::InputNotReady(retry_after)
            },
        )?;
    let cosmos_txns = fetch_cbft_tx_data(cosmos, cl_block_number).await.map_err(|e| {
        tracing::error!("fetch_cbft_tx_data: {e:?}");
        proof_builder::ProofError::InputNotReady(retry_after)
    })?;
    let cosmos_block = fetch_cosmos_block(cosmos, cl_block_number).await.map_err(|e| {
        tracing::error!("fetch_cosmos_block: {e:?}");
        proof_builder::ProofError::InputNotReady(retry_after)
    })?;

    tracing::info!("block: {i}, cl_block_number: {cl_block_number}, txns: {}", cosmos_txns.len());

    // for block i, find the contract call with graph_id in its input
    let mut withdrawals: Vec<(Address, [u8; 32], Vec<[u8; 16]>)> = Vec::new();
    for (graph_id, l2_contract_address) in withdrawal_events {
        let graph_ids = withdrawals
            .iter()
            .find(|(addr, _, _)| *addr == l2_contract_address)
            .map(|(_, _, graph_ids)| graph_ids.clone())
            .unwrap_or(vec![graph_id]);
        withdrawals.push((l2_contract_address, base_slot, graph_ids));
    }

    // merge the graph ids of a same contract into one

    let cosmos_block = serde_json::to_vec(&cosmos_block)?;
    tracing::info!("[push] block: {}, withdrawals: {:?}", i, withdrawals);
    Ok(CircuitStateBlock { cosmos_txns, cosmos_block, evm_block, withdrawals })
}

/// Fetches GOAT blocks `start..start + batch_size`, `concurrency` blocks at a time, in block order.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_state_chain(
    l2_contract_addresses: &str,
    proceed_withdraw_method_ids: &str,
    start: u64,
    batch_size: u64,
    execution_layer_rpc: &str,
    blocks_file: &str,
    genesis: &str,
    cosmos_rpc_url: &str,
    concurrency: usize,
) -> anyhow::Result<Vec<CircuitStateBlock>> {
    let l2_contract_addresses: Vec<Address> = l2_contract_addresses
        .split(',')
        .map(|s| {
            let addr = s.trim().trim_start_matches("0x");
            let bytes: [u8; 20] = hex::decode(addr).unwrap().try_into().unwrap();
            Address::from(bytes)
        })
        .collect();
    let proceed_withdraw_method_ids: Vec<[u8; 4]> =
        proceed_withdraw_method_ids.split(',').map(|s| hex_parse::<4>(s).unwrap()).collect();

    let genesis = if genesis == "goattest" { Genesis::GoatTestnet } else { Genesis::GOAT };
    assert!(start > 0, "Don't get genesis block from the consensus layer.");
    let base_slot: [u8; 32] = U256::from(16).to_be_bytes();
    // One client per layer for the whole batch, so blocks reuse their connections.
    let provider = RootProvider::<Ethereum>::new_http(Url::parse(execution_layer_rpc)?);
    let cosmos = HttpClient::new(cosmos_rpc_url)
        .map_err(|e| anyhow::anyhow!("Invalid cosmos rpc url {cosmos_rpc_url}: {e:?}"))?;

    let fetch_start = std::time::Instant::now();
    let blocks: Vec<CircuitStateBlock> = stream::iter(start..(start + batch_size))
        .map(|i| {
            fetch_state_block(
                &provider,
                &cosmos,
                &genesis,
                &l2_contract_addresses,
                &proceed_withdraw_method_ids,
                base_slot,
                i,
                // GOAT's block time is 3 seconds
                (batch_size + start - i) * 3,
            )
        })
        .buffered(concurrency.max(1))
        .try_collect()
        .await?;
    tracing::info!(
        "fetched blocks {start}..{}, {concurrency} at a time, in {:?}",
        start + batch_size,
        fetch_start.elapsed()
    );
    let block_bytes = serde_json::to_vec(&blocks)?;
    std::fs::write(blocks_file, block_bytes)?;
    Ok(blocks)
}

pub struct StateChainProofBuilder {
    client: Arc<ProverClient>,
    proving_key: zkm_sdk::ZKMProvingKey,
    verifying_key: zkm_sdk::ZKMVerifyingKey,
}

impl StateChainProofBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::with_client(Arc::new(ProverClient::new()))
    }

    /// Sets the program up on a prover client that other builders may share.
    pub fn with_client(client: Arc<ProverClient>) -> Self {
        let (proving_key, verifying_key) = client.setup(STATE_CHAIN);
        Self { client, proving_key, verifying_key }
    }
}

impl ProofBuilder for StateChainProofBuilder {
    fn client(&self) -> &zkm_sdk::ProverClient {
        &self.client
    }

    fn pk(&self) -> &zkm_sdk::ZKMProvingKey {
        &self.proving_key
    }

    fn vk(&self) -> &zkm_sdk::ZKMVerifyingKey {
        &self.verifying_key
    }

    fn name() -> String {
        "state-chain".to_string()
    }

    #[tracing::instrument(level = "info", skip(self, ctx))]
    fn build_proof(
        &self,
        ctx: &ProofRequest,
    ) -> anyhow::Result<(Vec<u8>, ZKMProofWithPublicValues, u64, f32)> {
        let ProofRequest::StateChainProofRequest { init_input, input_proof, blocks, .. } = ctx
        else {
            anyhow::bail!("Invalid state chain inputs");
        };

        let prev_receipt = if *init_input {
            None
        } else {
            let public_inputs = fs::read(format!("{}.public_inputs.bin", input_proof))
                .context("Read public input")?;
            Some(public_inputs)
        };

        let self_program_id = self.program_id()?;
        let (prev_proof, zkm_proof, zkm_public_values, zkm_vk_hash, zkm_version) =
            match prev_receipt.clone() {
                Some(public_inputs) => {
                    let proof_bytes =
                        fs::read(input_proof).context("Failed to read input proof file")?;
                    let zkm_vk_hash =
                        fs::read(format!("{}.vk_hash.bin", input_proof)).context("Read vk_hash")?;
                    let version_path = format!("{input_proof}.zkm_version.bin");
                    let zkm_version = fs::read(&version_path)
                        .with_context(|| {
                            format!("failed to read zkm_version file '{version_path}'")
                        })
                        .and_then(|raw_zkm_version| {
                            String::from_utf8(raw_zkm_version).with_context(|| {
                                format!("invalid UTF-8 in zkm_version file '{version_path}'")
                            })
                        })?;
                    let prev_proof =
                        classify_state_chain_output(&public_inputs).map_err(anyhow::Error::msg)?;
                    (prev_proof, proof_bytes, public_inputs, zkm_vk_hash.to_vec(), zkm_version)
                }
                None => (
                    StateChainPrevProofType::GenesisBlock,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    ZKM_CIRCUIT_VERSION.into(),
                ),
            };

        let input: StateChainCircuitInput = StateChainCircuitInput {
            prev_proof,
            zkm_proof,
            zkm_public_values,
            zkm_vk_hash,
            zkm_version,
            self_program_id,
            blocks: blocks.clone(),
        };
        // Generate the proofs.
        let (proof, cycles, proving_time) = tracing::info_span!("generate proof").in_scope(
            || -> anyhow::Result<(ZKMProofWithPublicValues, u64, f32)> {
                let mut stdin = ZKMStdin::new();
                stdin.write(&input);
                let elf_id = if ELF_ID.get().is_none() {
                    ELF_ID
                        .set(hex::encode(Sha256::digest(&self.proving_key.elf)))
                        .map_err(anyhow::Error::msg)?;
                    None
                } else {
                    Some(ELF_ID.get().unwrap().clone())
                };
                tracing::info!("elf id: {:?}", elf_id);

                proof_builder::prove_timed(
                    &self.client,
                    &self.proving_key,
                    &stdin,
                    ZKMProofKind::Groth16,
                    elf_id,
                )
            },
        )?;
        tracing::info!("State chain proof cycles: {}", cycles);

        self.client
            .verify(&proof, &self.verifying_key)
            .context("Failed to verify generated state chain proof")?;

        let input = bincode::serialize(&input)?;
        Ok((input, proof, cycles, proving_time))
    }

    fn save_proof(
        &self,
        ctx: &ProofRequest,
        _input: &[u8],
        _cycles: u64,
        proof: ZKMProofWithPublicValues,
    ) -> anyhow::Result<(String, usize)> {
        let ProofRequest::StateChainProofRequest { output_proof, .. } = ctx else {
            anyhow::bail!("Invalid state chain inputs");
        };
        let proof_bytes = proof.bytes()?;
        let proof_size = proof_bytes.len();
        let public_values = proof.public_values.to_vec();
        let public_value_hex = hex::encode(&public_values);
        let vk_hash = self.verifying_key.bytes32();
        proof_builder::artifacts::publish_artifacts(
            output_proof,
            &proof_bytes,
            &[
                (".public_inputs.bin", public_values.as_slice()),
                (".vk_hash.bin", vk_hash.as_bytes()),
                (".zkm_version.bin", proof.zkm_version.as_bytes()),
            ],
        )?;

        tracing::info!("Generate proof successfully, proof: {:?}", proof);
        Ok((public_value_hex, proof_size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// A block as JSON, minus what changes between fetches of the same block: the cosmos node
    /// that served the light block (behind a load balancer), and the order of the bytecodes,
    /// which come from a hash map and which the guest looks up by hash.
    fn comparable(block: &CircuitStateBlock) -> Value {
        let mut light_block: Value = serde_json::from_slice(&block.cosmos_block).unwrap();
        light_block.as_object_mut().unwrap().remove("provider");
        let mut evm_block = serde_json::to_value(&block.evm_block).unwrap();
        evm_block["bytecodes"].as_array_mut().unwrap().sort_by_key(|code| code.to_string());
        serde_json::json!({
            "cosmos_txns": block.cosmos_txns,
            "light_block": light_block,
            "evm_block": evm_block,
            "withdrawals": block.withdrawals,
        })
    }

    /// The JSON paths at which two values differ.
    fn differing_paths(a: &Value, b: &Value, path: String) -> Vec<String> {
        match (a, b) {
            (Value::Object(x), Value::Object(y)) => {
                let keys: std::collections::BTreeSet<&String> = x.keys().chain(y.keys()).collect();
                keys.into_iter()
                    .flat_map(|k| {
                        let missing = Value::Null;
                        let (x, y) = (x.get(k).unwrap_or(&missing), y.get(k).unwrap_or(&missing));
                        differing_paths(x, y, format!("{path}.{k}"))
                    })
                    .collect()
            }
            (Value::Array(x), Value::Array(y)) if x.len() == y.len() => (0..x.len())
                .flat_map(|i| differing_paths(&x[i], &y[i], format!("{path}[{i}]")))
                .collect(),
            _ if a != b => vec![path],
            _ => vec![],
        }
    }

    #[tokio::test]
    #[ignore = "requires public GOAT testnet3 RPC"]
    async fn concurrent_fetch_matches_sequential() {
        let execution_layer_rpc = std::env::var("EXECUTION_LAYER_RPC")
            .unwrap_or("https://rpc-legacy.testnet3.goat.network".to_string());
        let cosmos_rpc_url = std::env::var("COSMOS_RPC_URL")
            .unwrap_or("https://rpc.testnet3.goat.network/goat-rpc".to_string());
        let (start, batch_size) = (17781200, 6);
        let blocks_file = std::env::temp_dir().join("state-chain-fetch-test.blocks");
        let fetch = |concurrency| {
            fetch_state_chain(
                "0x0c7821F1C72181a2C710Eaa91d81120d7e009e41,0x60a5b099eE011018DD064F9eBD50d381C37b5e8b",
                "0xd3d8a3f4,0xd3d8a3f4",
                start,
                batch_size,
                &execution_layer_rpc,
                blocks_file.to_str().unwrap(),
                "goattest",
                &cosmos_rpc_url,
                concurrency,
            )
        };

        let sequential = fetch(1).await.unwrap();
        let concurrent = fetch(4).await.unwrap();

        let numbers: Vec<u64> =
            concurrent.iter().map(|b| b.evm_block.current_block.header.number).collect();
        assert_eq!(numbers, (start..start + batch_size).collect::<Vec<_>>());
        for (number, (s, c)) in numbers.iter().zip(sequential.iter().zip(&concurrent)) {
            let paths = differing_paths(&comparable(s), &comparable(c), String::new());
            assert!(paths.is_empty(), "block {number} differs at {}", paths.join(", "));
        }
    }
}
