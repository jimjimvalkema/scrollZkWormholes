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


global PADDED_CONTRACT_ADDRESS = [123,113,141,222,163,213,172,254,28,124,143,86,84,229,63,240,132,226,117,83,0,0,0,0,0,0,0,0,0,0,0,0];
global BALANCES_SLOT = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
global COMPRESSED_KECCAK_CODE_HASH = 0x0e1d42ab26af640fcf7451fab29af95616cde87b281b5d02cd6e5442a97fc1cb;
global POSEIDON_CODE_HASH = 0x0277abf217dc9e025e3cd539f1d9d366849a59648dcbae8a7441eb65aeaf4c0a;


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
                hash_path:  [0x072b45eb348b62fa3e07869adef6f702dddc988cd30703eeb4889ed2c81862cd,0x0000000000000000000000000000000000000000000000000000000000000000,0x0000000000000000000000000000000000000000000000000000000000000000,0x0000000000000000000000000000000000000000000000000000000000000000,0x0000000000000000000000000000000000000000000000000000000000000000,0x040278f59402e88b484bf3c68c3f53dbb0026f1afcc13a967d177cbd36e334e5,0x239aad518d9f5dd8fa7c63bc9d6abde611050dde90adb421aeabff1fb680636a,0x032bc815627dcdf25d4fcfad6b1048d9522395df5673f884a04826107e2158b5,0x2193d95f8015796035f0c5795d177f5d8641e033446648f1b0dfe040497dbc66,0x17ed2723e843738230c8d65ea06c7228302d107f651b6665e774ecf2bfba3e30,0x22270e10332df1cd672f676a6bcf39967b50e360ac8c9062f4ecd8b3bf869333,0x20f18406c35ca0d3ce2475152b5fcc2a553f5332ab1bc95ae6bc6be8bb3d418c,0x2fe44f6c8bb59f8c9b81c5d8ae2d7e79e70da5c60002a1f401012752281c5634,0x1cb9c89ece8019fdd57e718209f710dd2e0871efbeaa9da4fc8bf1ac123c583d,0x25ffbb30b3f7075913051649598a4f4667ffd277d8085937120561f084224597,0x022cbc3f13dfa4685ec6d58c70831b740ac2518820725cdaeff77a69fc9a8fcd,0x2bd44874aa404fac21c8ea23f69191f313bd92b38fa5ee8d7e74ad81ddb2e399,0x21978e77c4e955b838841137827c84cb773760cb33db8c9fbf5da80226e216a8,0x03d83eb6c65b507cc0479e49051513774fc2a42fdc1cf9112f5d003fe6325168,0x04037d526dd7f338d636085016e64d3cd727dcaad7b4dbab0c8a5d3434ee724b,0x0558199243121327ff43a4da959886fddfde23a5698b37b57a628f4223dd5abb,0x0b3fca6618acb696714156bba265992e021efca86317cf28dafdb2e30204e47f,0x127cc14b14554831091f8cd822d4a841a2e6071d6a0a777a11faa7a582620307,0x02b0d605e17a3e9effdd0781efe8c75c19084ebe5715225ff115983774050dcb,0x09a4fd36bc4d5d10f643b8f4c31ff6d37585a200c8b77c05c1449eaf1f7423ed,0x00813e52cdff9098cfca750f3f5f86e6864fe93da9ff4737c6b950bb7b3a909f],
                leaf_type: 4,
                node_types: [6,8,7,7,8,7,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],
                real_hash_path_len: 26,
                hash_path_bools: [true,false,true,true,false,true,false,false,false,false,true,false,true,false,false,true,true,true,false,false,true,false,false,true,true,false]
            },
            storage_proof: Hash_path_proof {
                hash_path: [0x2664a4f45d7b512e6bfc70507255cf7300082fea39883e4a92a7a2057068240e,0x0000000000000000000000000000000000000000000000000000000000000000,0x1d2c9037d0cd45a3677619b90f6f0c0be89f0aedcf3a911cf75f06bf3e149d89,0x1f145360db79a0c6060d3fef3f0d95ef47eaf65145c942a4c5da452f4c831505,0x17a2e9b822550e2ccf75d3fcff798c1e0964f9f889228f2d0b0fdfe7b0af6e19,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                leaf_type: 4,
                node_types: [6,8,8,8,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                real_hash_path_len: 5,
                hash_path_bools: [false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false]
            },
        },
            contract_balance: 0,
            header_rlp:[249,2,96,160,152,130,160,101,189,26,74,21,198,233,250,86,191,44,246,143,157,33,95,31,3,187,220,180,183,223,222,30,69,101,150,103,160,29,204,77,232,222,199,93,122,171,133,181,103,182,204,212,26,211,18,69,27,148,138,116,19,240,161,66,253,64,212,147,71,148,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,160,14,83,236,222,193,103,5,132,168,37,115,0,69,10,108,189,115,31,5,62,135,236,240,9,173,61,58,60,29,0,11,88,160,175,160,21,250,90,161,150,143,181,9,120,15,102,82,229,204,164,17,145,45,2,166,67,209,170,44,144,245,137,158,159,101,160,247,141,251,116,63,189,146,173,225,64,113,28,139,188,84,43,94,48,127,10,183,152,78,255,53,215,81,150,159,229,126,250,185,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,131,92,124,187,131,152,150,128,130,82,8,132,102,187,132,127,184,97,216,131,6,0,0,132,103,101,116,104,136,103,111,49,46,50,49,46,49,133,108,105,110,117,120,0,0,0,0,0,0,0,134,171,75,213,29,117,51,127,180,149,64,95,154,255,81,117,185,43,124,62,73,49,239,192,23,211,220,111,137,32,207,235,25,29,62,77,44,144,187,200,38,67,163,31,100,80,57,152,89,178,41,129,45,133,238,47,14,156,10,126,64,79,138,39,1,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,136,0,0,0,0,0,0,0,0,132,11,174,91,225,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            header_rlp_len:611,
            nonce_codesize_0:0x000000000000000000000000000000000000000000000f750000000000000001,
        };


    let secret = 2072661699086074886874540075110682606381032167987064181351256131438180528293;

    let remint_address = 0x93211e420c8F552a0e4836f84892a0D4eb5D6D54;
    let user_balance = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,22,196,171,190,190,160,16,0,0];
    let block_hash =  [196,242,7,118,241,250,8,230,140,138,47,239,144,198,85,67,43,21,176,142,189,83,92,234,70,199,96,180,195,4,118,73];
    let nullifier = hash_nullifier(secret);
    main(remint_address,user_balance,block_hash,nullifier,secret,storage_proof_data);
}
