use dep::ScrollStorageProver::{storage_proof_on_mapping,poseidon2_domain, get_state_root, split_byte32_to_fields};
use dep::ScrollStorageProver::{Hash_path_proof,Hash_paths_state_proof, Account_preimage_excl_storage};
use dep::std::field::bytes32_to_field;
use dep::std::hash::poseidon;
use dep::std::hash::keccak256;

// 54 is the highest value that still run in noirjs wasm
// might be enough since it can support scroll up to 18014398 billion account and for the contract to have 18014398 billion different slots
// splitting the proof up into account, storage proof seperately could increase the depth to 108 which would be 324518553000000000000 billion slots

// MAX_HASH_PATH_SIZE can be up to 32 to be proven in the browser. 248 to cover the full tree
// the account tree depth of sepolia is 23
global MAX_HASH_PATH_SIZE = 26;//248;//32; //this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
global MAX_RLP_SIZE = 650;//1000; //should be enough scroll mainnet wasn't going above 621, my guess is 673 bytes max + rlp over head. idk what overhead is tho.
// TODO actually find out what the largest value could be 


global PADDED_CONTRACT_ADDRESS = [32,239,76,197,214,129,152,172,172,222,68,104,16,115,20,166,41,82,45,110,0,0,0,0,0,0,0,0,0,0,0,0];
global BALANCES_SLOT = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
global COMPRESSED_KECCAK_CODE_HASH = 0x0614d811ed4ae0100b1be9d4c4c661e17fcfcde6dbf22a56d7006e84648dd21a;
global POSEIDON_CODE_HASH = 0x2ea440a83444a9a127efe8ee9e4b6edb87b803bdb69a6e95bab76cb8b460dd99;


struct Storage_proof_data {
    hash_paths: Hash_paths_state_proof<MAX_HASH_PATH_SIZE,MAX_HASH_PATH_SIZE>,
    contract_balance: Field,
    nonce_codesize_0: Field,
    header_rlp: [u8;MAX_RLP_SIZE],
    header_rlp_len: u32,
}

fn get_burn_address(secret: Field) -> [u8;32] {
    let hash:[u8] = poseidon::bn254::hash_1([secret]).to_be_bytes(32);//.as_array();
    let mut burn_address:[u8;32] = [0;32];
    // replace last 12 bytes with zero since address is only 20 bytes
    for index in 0 .. 20 {
        burn_address[index+12] = hash[index];   
    }
    burn_address
}

fn hash_nullifier(secret: Field) -> Field {
    let hashed_secret = poseidon::bn254::hash_1([secret]);
    poseidon::bn254::hash_2([secret, hashed_secret])
}

fn main(
        remint_address:pub Field, // gets the address to mint to
        user_balance:pub [u8;32], // amount to mint //TODO split into fields constaint golf
        block_hash:pub [u8;32], 
        nullifier:pub Field,
        secret: Field,
        storage_proof_data: Storage_proof_data,
    ) {
    // to prevent the proof being stolen from the mempool and used for a differen withdraw address
    assert(remint_address != 0x0);

    let computed_nullifier = hash_nullifier(secret);
    assert(computed_nullifier == nullifier, "computed nullifier doesnt match provided nullifier");

    // burn_address = our secret commitment
    let burn_address:[u8;32] = get_burn_address(secret);

    //-------------- account preimage--------------
    let account_preimage = Account_preimage_excl_storage { // = the whole account leaf preimage except storage hash since we need to compute it later here
        compressed_keccak_code_hash:COMPRESSED_KECCAK_CODE_HASH, // cannot be change afaik unless maybe self destruct but that is silly
        poseidon_code_hash:         POSEIDON_CODE_HASH, // 
        nonce_codesize_0:           storage_proof_data.nonce_codesize_0, // only changes if the contract creates another contract: https://ethereum.org/en/developers/docs/accounts/#an-account-examined
        balance:                    storage_proof_data.contract_balance, // always changes            
    }; 

    //------------ compute block hash ------------------
    let state_root = storage_proof_on_mapping(burn_address, BALANCES_SLOT, user_balance, PADDED_CONTRACT_ADDRESS, storage_proof_data.hash_paths, account_preimage);
    let computed_block_hash:[u8;32] = keccak256(storage_proof_data.header_rlp,storage_proof_data.header_rlp_len);
    assert(computed_block_hash == block_hash, "given block hash doesnt match computed block hash");

    //------------- check state root in rlp ----------------
    let state_root_rlp = get_state_root(storage_proof_data.header_rlp);
    assert(bytes32_to_field(state_root_rlp) == state_root, "computed state root from merkle proof doesnt match the one from the block header rlp");
}

#[test]
fn test_hashing() {
    let secret = 123;
    let address = get_burn_address(secret);
    let nullifier = hash_nullifier(secret);
    println(address);
    println(nullifier);
}

#[test]
fn test_get_state_root() {
    let header_rlp:[u8;607] = [249,2,92,160,239,37,169,176,180,227,63,164,8,23,74,123,2,50,96,72,192,223,169,179,175,31,225,216,123,74,73,232,114,130,59,90,160,29,204,77,232,222,199,93,122,171,133,181,103,182,204,212,26,211,18,69,27,148,138,116,19,240,161,66,253,64,212,147,71,148,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,160,22,96,101,252,118,165,64,236,30,201,68,228,168,228,9,200,217,97,91,119,98,21,4,239,255,21,78,1,50,248,232,248,160,136,102,42,69,64,99,89,76,135,191,116,65,216,161,127,113,49,212,190,59,37,30,139,65,60,85,44,161,45,226,246,216,160,158,25,2,237,43,125,57,186,32,212,200,246,195,128,119,200,198,67,196,165,185,217,54,244,106,106,21,249,173,46,18,143,185,1,0,0,2,16,0,4,0,0,64,0,0,32,0,0,128,64,32,0,4,0,0,34,0,32,16,8,16,18,0,0,80,1,1,5,16,0,0,32,2,8,0,16,0,128,0,0,0,0,0,0,0,64,0,0,32,2,4,0,0,0,4,0,32,0,0,0,0,128,0,4,112,32,0,2,0,0,8,0,0,0,0,0,0,8,16,0,0,0,0,160,1,0,0,0,0,0,8,0,0,0,0,66,16,0,16,0,0,4,0,0,0,8,8,0,0,0,64,32,16,64,0,0,0,0,16,0,0,2,0,0,1,4,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,64,0,0,0,8,129,128,0,0,0,0,7,65,2,64,130,0,0,1,32,0,64,0,16,0,0,0,0,0,32,0,2,0,32,64,0,16,0,0,0,0,0,0,0,32,32,0,0,34,0,0,0,32,0,0,128,2,1,0,64,0,0,20,0,0,32,0,0,8,0,0,0,16,0,0,32,0,128,16,0,132,0,0,0,2,0,0,4,0,0,2,4,0,0,0,0,32,17,0,128,0,0,0,32,0,12,0,0,0,2,131,98,190,31,131,152,150,128,131,14,199,206,132,102,104,97,14,184,97,216,131,5,3,32,132,103,101,116,104,136,103,111,49,46,50,48,46,49,133,108,105,110,117,120,0,0,0,0,0,0,0,98,35,151,26,49,19,62,111,213,69,22,123,70,156,179,46,68,8,66,169,246,237,189,150,167,155,212,142,202,153,105,118,50,142,15,6,182,252,51,82,55,245,167,10,219,154,87,83,247,147,198,131,202,118,201,93,24,196,4,87,170,156,181,215,1,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,136,0,0,0,0,0,0,0,0];
    
    let state_root:Field = 0x166065fc76a540ec1ec944e4a8e409c8d9615b77621504efff154e0132f8e8f8;

    let state_root_rlp = get_state_root(header_rlp);
    assert(bytes32_to_field(state_root_rlp) == state_root, "state root doesnt match. Did the header layout change?");
}

#[test]
fn test_main() {
    let storage_proof_data = Storage_proof_data {
        hash_paths :Hash_paths_state_proof{
                account_proof: Hash_path_proof {
                hash_path:  [0x0300e07d6bb9d47f621f3509af421b6e2cb37c1386bb734d9fdadd904110d5bf,0x2d2a0cd757ec447f47d57f13349d283c8dbaa0efc368eba4905a2ba064429bf4,0x13b340c5ded3f20693a7821f158b5e9dc54302725f4739337b6e7ae4e98a1afd,0x04b3300a56001fc626c5eee6b3d14819d9da3863fb884328cca6f8e604b406a3,0x21819e5703a44217d03520d58a75d452c4e1161bc46c5c4d75ad4b55d01e28bd,0x283e19df938a9b0d69e995b83d49409e88e1648644d85ae606bacf3eaf65dbf3,0x28b1c7283939550ed5fe7e4c153ea13f5743bb571382537f1b6b77abc95b3e6d,0x0c3a4ed67fd7aeebdd1c67da3031cba0d09fa488b6a8e4728589ed61cc0714cf,0x2cc29d44cb6a920a86548f0cec2ed1e0bd6a797e0f6a8693189eb7696b8b45ce,0x049cc651855d4bfd1cf35b07ce6289292e747fcdf1b0adb9483113498382c8a1,0x0504510f777873080244f55b09c5d55f8ba3077a023f37e04246a78b56ebe6a0,0x1d7921db10348d2697e92538625438619e7f3d887877386a5f8c1c996ca98b98,0x26f3a2201d9286c3c5a15e380ee87f812294a686d950f5212cd3398ac21ef796,0x0c4096dd0f1a18c5934cc5d2fb5868d653e4d929e562fb0489bf8e7f99592a18,0x1f6eb0545c8e9a362429f0d47f55b3a74ea542b9c212a3e5afdfcf168cb8069e,0x123ba777c7743ea7d4bfe0d6dd0e215d7c21d037e2ed65bc95347a99eaccdbc4,0x026b94adb0b48ceec6bae20c4855ed0dda7684f21912fda62da7c9f3e49a8ed0,0x06b2d3a7225a0b3b781051d6dabc48c5a89cbab55cc0e135acbe90f5399ba4c0,0x2062769d8f5b2877e4ff5f87a4f4e6cfbc28f0cc9b0eba18ddb66bf83d83cb04,0x1c9ed1df032a2d1f39ecba94b86e547bfd633cd8d1cef470601d7ad781b33819,0x15e9e8bd788c977c5a548e7b87daa015718e564bfc61e2c3c2fcd26b11ed9f43,0,0,0,0,0],
                leaf_type: 4,
                node_types: [6,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,0,0,0,0,0],
                real_hash_path_len: 21,
                hash_path_bools: [false,true,true,true,false,false,false,true,false,false,false,true,false,false,true,false,false,false,false,false,false,false,false,false,false,false]
            },
            storage_proof: Hash_path_proof {
                hash_path: [0x185627c8eacda1440e9fe853562b0d50108a92c762b145e9363f2f11620f43e2,0x0db87bac9757352229b10dc6b19ebde66593c71f0d8cd78b85c5becf191bf740,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                leaf_type: 4,
                node_types: [7,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                real_hash_path_len: 2,
                hash_path_bools: [false,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false]
            },
        },
            contract_balance: 0,
            header_rlp:[249,2,96,160,225,238,118,91,87,48,70,57,3,242,17,133,138,118,231,188,239,179,27,83,81,144,23,74,66,78,121,120,42,246,117,103,160,29,204,77,232,222,199,93,122,171,133,181,103,182,204,212,26,211,18,69,27,148,138,116,19,240,161,66,253,64,212,147,71,148,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,160,18,97,71,80,17,144,95,92,142,3,146,50,66,251,10,107,133,41,16,219,77,232,152,233,65,13,114,142,163,150,186,225,160,250,213,15,189,192,179,95,214,122,49,123,142,238,229,96,79,59,101,61,166,99,240,27,187,66,253,132,239,15,125,194,74,160,91,161,115,204,140,18,81,101,71,106,91,95,0,110,38,19,100,160,151,245,253,150,130,66,160,234,164,87,218,229,2,226,185,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,32,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,131,90,235,200,131,152,150,128,130,134,70,132,102,178,34,32,184,97,216,131,5,6,0,132,103,101,116,104,136,103,111,49,46,50,49,46,49,133,108,105,110,117,120,0,0,0,0,0,0,0,24,7,11,250,241,11,175,62,210,219,174,34,99,179,225,90,63,127,78,20,229,132,144,206,198,48,128,180,47,113,112,134,49,80,156,251,17,114,56,20,34,78,86,37,191,132,122,55,137,237,190,31,30,34,85,28,120,26,30,72,190,86,105,230,0,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,136,0,0,0,0,0,0,0,0,132,5,187,77,164,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            header_rlp_len:611,
            nonce_codesize_0:0x0000000000000000000000000000000000000000000017200000000000000001,
        };


    let secret = 9520147284186906681642775079794917743430488779909885571957378649814670023808;

    let remint_address = 0x93211e420c8F552a0e4836f84892a0D4eb5D6D54;
    let user_balance = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,22,196,171,190,190,160,16,0,0];
    let block_hash =  [40,222,236,64,8,66,184,109,58,187,165,118,40,54,110,45,24,241,111,76,168,95,252,62,140,252,194,171,48,227,110,41];
    let nullifier = hash_nullifier(secret);
    main(remint_address,user_balance,block_hash,nullifier,secret,storage_proof_data);
}