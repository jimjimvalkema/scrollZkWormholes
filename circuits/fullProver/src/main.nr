use dep::ScrollStorageProver::{storage_proof_on_mapping, get_state_root};
use dep::ScrollStorageProver::{ Hash_paths_state_proof, Account_preimage_excl_storage};
use dep::std::field::bytes32_to_field;
use dep::std::hash::poseidon;
use dep::std::hash::keccak256;

// 54 is the highest value that still run in noirjs wasm
// might be enough since it can support scroll up to 18014398 billion account and for the contract to have 18014398 billion different slots
// splitting the proof up into account, storage proof seperately could increase the depth to 108 which would be 324518553000000000000 billion slots
global MAX_HASH_PATH_SIZE: u32 = 248;//248;//32; //this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
global MAX_RLP_SIZE: u32 = 850;//1000; //should be enough scroll mainnet wasn't going above 621, my guess is 673 bytes max + rlp over head. idk what overhead is tho.
// TODO actually find out what the largest value could be 

global PADDED_CONTRACT_ADDRESS: [u8;32] = [33,208,131,41,94,37,81,229,129,92,47,11,76,183,61,226,83,145,6,183,0,0,0,0,0,0,0,0,0,0,0,0];// 0x21d083295e2551e5815c2f0b4cb73de2539106b7000000000000000000000000
global BALANCES_SLOT:[u8;32]  = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
global PARTIAL_NULLIFIERS_SLOT:[u8;32]  = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6];
global COMPRESSED_KECCAK_CODE_HASH: Field = 0x0e8e0b42b49cc167cf5bd04ee737d0b1e1312e5cc11f8817612271f464fc2924;
global POSEIDON_CODE_HASH: Field = 0x0e630c824b73bb5c6321b6342d9f22ae2deeb567cd23d85a80ff0dbeff4ec533;

struct Contract_proof_data<let R:u32> {
    balance: Field,
    nonce_codesize_0: Field,
    header_rlp: [u8;R],
    header_rlp_len: u32,
}

fn get_burn_address(secret: Field) -> [u8; 32] {
    let hash:[u8; 32] = poseidon::bn254::hash_1([secret]).to_be_bytes(); //.as_array();
    let mut burn_address:[u8;32] = [0; 32];

    // replace last 12 bytes with zero since address is only 20 bytes (noir doesnt support a nicer method hence whacky for loop)
    for index in 0..20 {
        burn_address[index+12] = hash[index];
    }
    burn_address
}

// nonce makes sure the hash is never the same even when the amount is different
// secret is so others cant try and find the pre-image (since this hash is posted onchain)
fn hash_nullifier(amount: Field, nonce: Field, secret: Field) -> Field {
    poseidon::bn254::hash_3([amount, nonce, secret])
}

// nonce makes sure the hash is never the same even when the amount is different
// secret is so others cant try and find the pre-image (since this hash is posted onchain)
fn hash_nullifier_id(nonce: Field, secret: Field) -> Field {
    poseidon::bn254::hash_2([nonce, secret])
}

fn lower_then_or_equal(a: Field, b: Field) -> bool {
    !std::field::bn254::gt(a, b)
}

//TODO check if its okay id prevNullifier id maps to a nullfier which is 0x000000000
fn main(
    //----- public inputs
    remint_address: pub Field,// the address to re-mint to
    withdraw_amount: pub Field,
    nullifier: pub Field,
    nullifier_id: pub Field,
    block_hash: pub [u8; 32],
    //-----very privacy sensitive data -----
    secret: Field,//burnaddress is derived from secret // TODO instead of using a secrets use public cryptography shit so hardware wallets dont have to create a whole ass proof. Also makes complexity lower for hot wallets to ensure safety and better compatability with metamasksnap.
    burned_balance: [u8; 32], //TODO split into fields constraint golf or just as a field (also gas golf) (assumes a balance never > FIELD_LIMIT)
    nonce: Field, // nonce to create a nulliefier from to track encrypted spend_amounts
    prev_nullifier_id: Field, // just here for the storage proof of prev_nullifier, since prev_nullifier already contains all info
    prev_spend_amount: Field,
    burn_addr_storage_proof: Hash_paths_state_proof<MAX_HASH_PATH_SIZE,MAX_HASH_PATH_SIZE>,
    prev_nullifier_storage_proof: Hash_paths_state_proof<MAX_HASH_PATH_SIZE,MAX_HASH_PATH_SIZE>,
    // ---- insensitive data (is private to reduce gas) --
    contract_data: Contract_proof_data<MAX_RLP_SIZE>
) {
    // to prevent the proof being stolen from the mempool and used for a differen withdraw address
    // TODO check if you realy need to do this? Tornadocash something similair tho.
    assert(remint_address != 0x0);

    //------------- check state root is in blockhash ----------------
    let state_root_rlp = get_state_root(contract_data.header_rlp);
    let computed_block_hash:[u8;32] = keccak256(contract_data.header_rlp, contract_data.header_rlp_len);
    assert(computed_block_hash == block_hash, "given block hash doesnt match computed block hash");

    //-------------- account preimage--------------
    let contract_account_preimage = Account_preimage_excl_storage { // = the whole account leaf preimage except storage hash since we need to compute it later here
        compressed_keccak_code_hash:    COMPRESSED_KECCAK_CODE_HASH, // cannot be change afaik unless maybe self destruct but that is silly
        poseidon_code_hash:             POSEIDON_CODE_HASH, // 
        nonce_codesize_0:               contract_data.nonce_codesize_0, //storage_proof_data.nonce_codesize_0, // only changes if the contract creates another contract: https://ethereum.org/en/developers/docs/accounts/#an-account-examined
        balance:                        contract_data.balance //storage_proof_data.contract_balance, // always changes            
    };

    //------------ state proof of mapping(burn_address -> burned_balance) ------------
    // burn_address = our secret commitment
    let burn_address:[u8;32] = get_burn_address(secret);
    // check burned_balance and burn_address with a storage proof
    let state_root_burn_addr = storage_proof_on_mapping(
        burn_address,
        BALANCES_SLOT,
        burned_balance,
        PADDED_CONTRACT_ADDRESS,
        burn_addr_storage_proof,
        contract_account_preimage
    );
    //TODO use bytes32_to_field once
    assert(
        bytes32_to_field(state_root_rlp) == state_root_burn_addr, "computed state root from the burn address merkle proof doesnt match the one from the block header rlp"
    );

    //--------prev nullifier------------
    if (nonce != 0) {
        // verify that the nullifier exist onchain with a storage proof
        // cant do this outside the circuit since that links prev_nullifier_id with the nullifier_id
        let prev_nullifier: [u8;32] = hash_nullifier(prev_spend_amount, nonce - 1, secret).to_be_bytes();

        let state_root_prev_nullifier_id = storage_proof_on_mapping(
            prev_nullifier_id.to_be_bytes(),
            PARTIAL_NULLIFIERS_SLOT,
            prev_nullifier,
            PADDED_CONTRACT_ADDRESS,
            prev_nullifier_storage_proof,
            contract_account_preimage
        );

        assert(
            bytes32_to_field(state_root_rlp) == state_root_prev_nullifier_id, "computed state root from the prev_nullifier_id merkle proof doesnt match the one from the block header rlp"
        );
    } else {
        // we dont need to check prev_nullifier_id since it doenst exist and we can keep prev_spend_amount at 0
        // TODO make the nullifier proof a recursive proof so the first tx is ~2x faster to proof
    }

    // ----- new_spend_amount-------------
    // @WARNING TODO watch out for overflows (solution?: make sure max supply of coin is < FIELD_LIMIT inside contract)
    let new_spend_amount: Field = withdraw_amount + prev_spend_amount;
    //new_spend_amount < burned_balance
    // TODO this burns 1 wei because i cant do <=
    // should i just do new_spend_amount == new_spend_amount || secret < new_spend_amount
    assert(lower_then_or_equal(new_spend_amount, bytes32_to_field(burned_balance)), "withdraw_amount too large, new_spend_amount is larger than burned_balance");
    let computed_nullifier: Field = hash_nullifier(new_spend_amount, nonce, secret);
    assert(
        computed_nullifier == nullifier, "public input: nullifier, doesnt match the one computed in the circuit"
    );

    // ----- nullifier_id -------------
    let computed_nullifier_id = hash_nullifier_id(nonce, secret);
    assert(computed_nullifier_id == nullifier_id, "computed nullifier doesnt match provided nullifier");
}
