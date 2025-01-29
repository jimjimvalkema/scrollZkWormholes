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


global PADDED_CONTRACT_ADDRESS = [240,25,43,233,207,78,162,150,224,95,255,227,50,113,19,59,190,3,42,223,0,0,0,0,0,0,0,0,0,0,0,0];
global BALANCES_SLOT = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
global COMPRESSED_KECCAK_CODE_HASH = 0x1dfc3016ce6256802e16d9124afb52f41291a6bf29697a4e6bf1b76be2f2d62c;
global POSEIDON_CODE_HASH = 0x18531aae70f67481b2d8785fafd0072fd12132744350dadfbc9a12a34295c562;


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
                hash_path:  [0x2cda74008fc6c5624cf8a15bcd95827a4e98a879ac9aab992750d0de21ecc0af,0x0000000000000000000000000000000000000000000000000000000000000000,0x0140514493160e2aaacad7cb8da281be65d8238e2fa49d72efff8d8d2b1c05ea,0x16cfef9ba68a34286a36984ff06a0068610ae2fd62dee373cdb8d7ae415ad2e9,0x12c2cbbf3533b3da9255a468e2c7fe7387e39bda618f19c79e0f9a6de7d35591,0x200716a9d3839049aedba778efae30c2767a76cd439a4999d79f64c640a09608,0x21fe420bad8be938caffad006b72b9a02a61a6098da0a2598e80d3c1fc07606a,0x11fa2fdcd5911851059f0b7dc0e3d99d313ffcb98fa3be8096883d65b5d0391c,0x1690a6c4ba90fb67124ec634b7c252721ba8e52a94b8f68a4083886d92861003,0x1564f138d0232861c33cabbb1129a981f43ae775862e9b5ee322d39892fd8c1f,0x30491b02c60dde1f055645a66752f52e8fad7d1ba2e2b7bafbc0071728386707,0x289e9cc505a354a0b082056732a6b2309a3ad9894612a5630370cebeb1ab789a,0x2c310dc7d5f5d75c6a5abdff1e8847b5cc25e91c70ddb364cb17f83e8e409388,0x0d399a80a008fea6d0b7597e735abec6ac2324998d3201c1050d4e5438fbb5b4,0x2812a13684b234a57c0c6e7aa5cabd718a243cedd238896a6b02b6e3e8880938,0x0d06d62c600fdd18df4d77f573267e30f9b5c7f84625b181909717bb9fe5bbfc,0x2a7a720b0804d3bb4dd5b464e19b774e0bdfa5b8f5c59c2b93bb51fd2e7b510b,0x0140f24fa34048124d1fc0f3d5aa14978a53a1ed2b825f6bdce9478d6fa11e48,0x1bb8db101d1b552d3ca253f3d7185a74a5dafe590e8c285df2b13714ae8f2d78,0x2601bbd391d255299e8fac2cd0d840b9eca1196892e9e481e6d4bc8d279eef88,0x1a057fca72fb94d7e1bdff2e49335f11a8b2506062f0a5684816233f9305b90b,0x2dbd493f8d71a509fc86c350de65be550a8ae43e2aee814750b01d186fc2e2f2,0x0dedd88f153ca6d7287d748a949fa5d8ed3f1c9e657beb41ed6a564920e8102e,0,0,0],
                leaf_type: 4,
                node_types: [6,8,9,8,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,0,0,0],
                real_hash_path_len: 23,
                hash_path_bools: [false,false,false,false,false,false,false,true,false,false,true,false,true,false,false,true,false,false,false,true,false,false,true,false,false,false]
            },
            storage_proof: Hash_path_proof {
                hash_path: [0x181209df932ec46541a2c56ee695409d5a7020864574c787d2b8c91b6e1fa0ca,0x01e04c8b89fee8eb81420738af2a7bfc2aa87b175870541d5b28adf4afa29d7b,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                leaf_type: 4,
                node_types: [7,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                real_hash_path_len: 2,
                hash_path_bools: [false,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false]
            },
        },
            contract_balance: 0,
            header_rlp:[249,2,96,160,48,60,161,1,246,53,206,180,31,149,5,253,222,95,147,78,2,97,71,233,212,40,94,86,221,143,33,14,23,210,126,48,160,29,204,77,232,222,199,93,122,171,133,181,103,182,204,212,26,211,18,69,27,148,138,116,19,240,161,66,253,64,212,147,71,148,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,160,34,20,194,34,29,72,214,29,236,195,98,99,75,194,48,70,126,12,79,189,191,91,119,210,116,72,141,11,217,48,43,87,160,192,232,31,52,76,244,227,131,87,38,39,3,131,32,248,109,157,210,87,64,85,19,109,76,236,56,168,111,98,149,56,113,160,83,160,42,63,248,160,231,200,79,90,228,30,210,133,120,223,14,153,142,109,101,177,37,61,185,66,197,1,9,169,153,193,185,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0,0,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0,0,0,0,0,0,0,2,131,122,112,25,131,152,150,128,130,150,90,132,103,152,216,17,184,97,216,131,5,8,0,132,103,101,116,104,136,103,111,49,46,50,49,46,49,133,108,105,110,117,120,0,0,0,0,0,0,0,164,118,119,90,12,229,60,182,207,20,23,172,91,184,105,40,51,102,233,210,46,141,93,20,52,96,209,83,172,143,88,55,106,108,152,251,37,98,139,158,64,37,150,151,48,133,64,230,115,37,222,71,16,148,35,247,5,190,40,89,222,41,234,204,1,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,136,0,0,0,0,0,0,0,0,132,2,202,55,30,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            header_rlp_len:611,
            nonce_codesize_0:0x000000000000000000000000000000000000000000000fa40000000000000001,
        };


    let secret = 10173446961174289388812552901958304618826698668105630089564208978828340780706;

    let remint_address = 0x93211e420c8F552a0e4836f84892a0D4eb5D6D54;
    let user_balance = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,22,196,171,190,190,160,16,0,0];
    let block_hash =  [130,61,91,35,58,45,112,213,46,56,69,18,62,13,122,78,142,72,119,148,200,202,142,26,79,34,135,60,85,4,14,112];
    let nullifier = hash_nullifier(secret);
    main(remint_address,user_balance,block_hash,nullifier,secret,storage_proof_data);
}