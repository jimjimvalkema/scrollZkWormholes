use dep::ScrollStorageProver::{storage_proof_on_mapping,poseidon2_domain, get_state_root, split_byte32_to_fields};
use dep::ScrollStorageProver::{Hash_path_proof,Hash_paths_state_proof, Account_preimage_excl_storage};
use dep::std::field::bytes32_to_field;
use dep::std::hash::poseidon;
use dep::std::hash::keccak256;

// 54 is the highest value that still run in noirjs wasm
// might be enough since it can support scroll up to 18014398 billion account and for the contract to have 18014398 billion different slots
// splitting the proof up into account, storage proof seperately could increase the depth to 108 which would be 324518553000000000000 billion slots
global MAX_HASH_PATH_SIZE = 248;//248;//32; //this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
global MAX_RLP_SIZE = 850;//1000; //should be enough scroll mainnet wasn't going above 621, my guess is 673 bytes max + rlp over head. idk what overhead is tho.
// TODO actually find out what the largest value could be 


global PADDED_CONTRACT_ADDRESS = [3,138,137,160,240,136,37,6,222,216,103,251,70,112,33,6,39,109,187,144,0,0,0,0,0,0,0,0,0,0,0,0];
global BALANCES_SLOT = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
global COMPRESSED_KECCAK_CODE_HASH = 0x0e37397f828ee3a48bf46a8b6acc294986b0e9557df56b338339ea655fd6b915;
global POSEIDON_CODE_HASH = 0x04b83ef097ba563cff61e753d6a8a911dd0be46f232a785e29b0de79b0cb49b7;


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
fn test_main() {
    let storage_proof_data = Storage_proof_data {
        hash_paths :Hash_paths_state_proof{
                account_proof: Hash_path_proof {
                hash_path:  [0x2624784757d9f17b90f7ad5a05a0692004af65de463b994f6da0597a4efe0481,0x24a5bf5ca387f39afe280ddd39cadc812ecde5d7e922ade3671b0505bc102c0a,0x0000000000000000000000000000000000000000000000000000000000000000,0x0b0ffb11df22c15ac54489c9630b1853b4261ce8a3b98eb590e84202ae24b483,0x20c598679410b424d752c0fe36164dde4f6d4591afde39fc01d6b9eacbc2e7b7,0x0704e33e5aa439ede96220e94765c53278dd819fbc9f594f9860bbae43501475,0x110e4a5255cce56ae74528969d3ced01df293d2a7baf0ac1b49937102b765bf8,0x1f7a0bb3c4042beef8c460de72d20bd1045bbbf5812378d5b9c50a6f2ca1d3d1,0x2a4098e336b661247e2f434af96fe8bdb0786410de7feef881ffc443e5fdeae4,0x18f8845fdc9e14762a7e152288c09ba68d51aa5a41905616f47f4c2d95bf51e0,0x14cb4cd07556e5095ec307bbc9fc5dd9ca424faf86dcf2565b639583563ecedd,0x0aff0891520a4ba94f233b066232545c7244a7df7229bf5a7bd8da2ba5adcf15,0x02348f58209ceb002721d02725da7ef5c3789ddcc30d5afe310cccca5c778f52,0x205a0067ef4085c907c0ea1cf0ab95b9235514a98731c97c77357b8be1ee5e27,0x09a27dfec15392669b88773cd13508702c7b758842950a7cf57091b58ba6a811,0x09e1c040074d1b38f957d530021fb4afefbc1bfa1835faa714e24418e4533196,0x1d930b4b7ac09c741a162888105e6be2ba58cfeed88fb947fc575faab2a7acff,0x22c2a57f5aa072a4b09681ad3960c99de7c91f3ce83fd7e7e253f829f82676c5,0x24f448d3b3b9b228c950afc522b9686fac2d1fda2af4a5f6271a6280f0cc3cf2,0x3062a0c9103f16600cca62b7cdfd6671d3dbda6be1bf5532e83fde2cd32702d2,0x28abc9f56fe02d4ba0993b02317690392688799bde75896d9a37864ce415eb5c,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                leaf_type: 4,
                node_types: [6,7,8,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                real_hash_path_len: 21,
                hash_path_bools: [true,true,false,false,true,true,true,false,true,false,false,false,false,true,true,false,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false]
            },
            storage_proof: Hash_path_proof {
                hash_path: [0x14a7306dd560b0dfe226f978debb7b95af092c8d5a61f22121e07f4344784683,0x0570a963b67066143a005b76f133e73e08ba04b30413f94b729975ade01bd1bd,0x0a07cf995d6cd168df2da1a55dcd0db2e876be6de7162a61c2bbe12f3aad2e5e,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                leaf_type: 4,
                node_types: [7,9,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                real_hash_path_len: 3,
                hash_path_bools: [false,false,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false]
            },
        },
            contract_balance: 0,
            header_rlp:[249,2,96,160,77,71,36,4,65,227,230,23,143,13,153,69,22,243,51,105,220,227,98,242,125,36,2,245,82,124,24,105,162,168,241,9,160,29,204,77,232,222,199,93,122,171,133,181,103,182,204,212,26,211,18,69,27,148,138,116,19,240,161,66,253,64,212,147,71,148,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,160,0,40,172,78,99,183,111,238,76,101,198,46,62,229,158,123,23,137,66,76,142,174,93,164,16,188,218,16,43,196,47,127,160,36,152,177,98,145,218,118,65,9,230,180,52,72,125,124,231,218,150,21,165,123,28,141,121,108,190,232,119,24,90,93,248,160,5,107,35,251,186,72,6,150,182,95,229,165,155,143,33,72,161,41,145,3,196,245,125,248,57,35,58,242,207,76,162,210,185,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,131,79,201,2,131,152,150,128,130,82,8,132,102,136,28,226,184,97,216,131,5,4,8,132,103,101,116,104,136,103,111,49,46,50,49,46,49,133,108,105,110,117,120,0,0,0,0,0,0,0,150,53,4,221,17,65,100,204,21,22,62,65,91,250,167,186,75,71,36,199,2,114,19,102,178,168,24,100,124,192,107,49,7,202,17,15,245,154,200,15,78,147,188,52,85,154,19,143,145,187,195,29,182,101,187,209,215,150,69,242,101,78,9,160,1,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,136,0,0,0,0,0,0,0,0,132,28,16,139,249,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            header_rlp_len:611,
            nonce_codesize_0:0x00000000000000000000000000000000000000000000157a0000000000000001,
        };


    let secret = 123;

    let remint_address = 0x93211e420c8F552a0e4836f84892a0D4eb5D6D54;
    let user_balance = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,136,156,6,120,119,192,96,0,0];
    let block_hash =  [252,172,152,122,85,237,218,38,249,252,203,156,70,20,227,192,44,55,48,55,140,38,225,18,172,145,10,230,238,201,204,102];
    let nullifier = hash_nullifier(secret);
    main(remint_address,user_balance,block_hash,nullifier,secret,storage_proof_data);

}

// #[test]
// fn test_storage_proof_on_mapping() {
//     // input
//     let user_address: [u8;32]       = [0,0,0,0,0,0,0,0,0,0,0,0,68,2,193,40,194,51,125,122,108,76,134,123,230,143,119,20,164,224,100,41];    // 0x4402c128c2337d7a6c4c867be68f7714a4e06429
//     let slot: [u8; 32]              = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];                                    // slot = 0
//     let user_balance:  [u8; 32]     = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,144,6,97,216,175,76,134];                           // 0.040539413963295878
//     let padded_contract: [u8;32]    = [83,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0];                                    // 0x5300000000000000000000000000000000000004 WETH on scroll (is a system contract thats why address looks weird)

//     // proof data
//     let hash_paths = Hash_paths_state_proof {
//         storage_proof: Hash_path_proof {
//             hash_path:  [0x082fd83e1176c02bba56005b3ba042af371971b4716f243642fca2a35a975040,0x0000000000000000000000000000000000000000000000000000000000000000,0x0000000000000000000000000000000000000000000000000000000000000000,0x1dbb1b961bc57d29f8b809aea22725896f8fe0054b90fb1a0f20ef8ce6b348e5,0x2cbc648029cf765385f6a17be45bbe74628c15d4c08f8d5e3f4491d94ae177e3,0x1eaff424e9893b368db781d66aee078fa2e932a269c009b6951586a5063bb3fb,0x2fde6d7e33e7c0dbf7448021a23e1b9f861de9906be91401e32987c506fa0a38,0x2acc21883e7d177c905ca2431c11fed214eebeaf95bb5bb3ff18b6988bcd2f6c,0x064fe3c43019c279d94c50619936c695080152678ca4448656e54790b124ba10,0x0e3a034343d14f2e9fa79bc58f3c5e83212ab34ad4216494ce5d0ba69a24129f,0x1e01222677655045108f8adabfb6b5aae23d15b6e8b865b885d22677930b1327,0x279df33aa48b973b0c4711959ba4032c91115266da7d46aa1eef4d5b4df50529,0x2c516cd8168873553bf5613fa108cf158db9f77356a14e5999a089bcb30bcc0d,0x169c51364a1a5d0d2fdf569654fdbb01f0fc57ce96f51224ace6c2b122a278f2,0x17ddf467aa6ad4be84637262c8bde743f303851b55a90cecaeb62f20949dd26a,0x0d0f3ad20d01ebbc06dddc8a4a4969088c6306a59e0941d09c608b86cddedf50,0x2704a07ac2ab2eef36c79b8e22eb2ebc49dfe7417500b04aac96b6f3babb802c,0x1dd281308230419c26bcd28b8ed40c561922c8c881e552f76c6575d16863e5ec,0x13a303bbb1e8cf20f48dd19ae218fda161c83fa10a7915615f0cc7028be36e4d,0x1590f4aaba59ff46a09d7a6a152cbf27280c2fbaa4bb94aa3eefab3bbd7d6e19,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
//             node_types: [6,7,8,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
//             leaf_type:  0x04,
//             real_hash_path_len: 20
//         },
//         account_proof: Hash_path_proof {
//             hash_path:  [0x21fb69ccdb00e6eaeaf7fc1e73630f39f846970b72ac801e396da0033fb0c247,0x1509aaaacf0678c3da394ea3edc21dc3c48767a85544a8f435b69f87ddfbaf0a,0x2fc2e33fdb53f97cdfc63e66de1e6a497a98b8d109c4f88a1eea4881f0929526,0x09ba87b2bd7facc2a4c986d82a5cb4001468843a60063c78a8d250b56f448377,0x160bcff072cec6d5f61ed69d2ed26cf539ae10655dd8a5a625ddf933ca1a42e4,0x0f7f936cd304525d85e1b33fedc1f62b9bfd87030ffb7b843eacd445fc4aea7f,0x242415f663834078570a91f27e9a1bcee2d0c0a0936c1010fe0d92c8ea935a18,0x2c342e07f95e2472f32bf2637467f30a2343e3f4fc702ac088c7e196d4de708b,0x134c58331016b26e8e3eedd0955eb8a54dab8e290ea9b957f4713cc79be917a6,0x0258b45271d86dfd4706c256753a684f08a05d258a5fff6750b0e2fd32e1cf4d,0x13c97981b6360a26dbe4f4694175d1d9a0e248ba734bf9e9e4d57df3c53f2437,0x1c41fc3e5ece5c5d2ccb67595d3a89fb39d43b32827f0464dd6aeb8f1a9ca701,0x0466fc11eb066d337c51cf870f18084e95000e890245833bcb16a134a22c4723,0x149966c5c9cb6966c568fb099c5385b0b4831be1f29f3592833749fb15bf405d,0x2309d7599612bb43f1bb17e40747eef76c254d444daaae064052edd1972f4440,0x20641a9afc11694b5a8c8acec09dc9f70a75fbc7914d1f5e9a41f15cd00665ae,0x2f98ca34e139c1057f0a30611814d34de4d80813497d7c9c863e697c95aa3cb5,0x0dc44be05703a33acb8c11756ad727c227fd086c46469a26a7a9d6750f439616,0x269ae40a8f39ab073983fb6fe0e384a865bcc21ec6e09e307fcc8692a6151ebc,0x0e8692bbc1d31269263cef16273badc1aebc37f1047bcd03c117a82c5b878610,0x2ad53eebc0132ed6cefb20cb9bb3379d8e7aa0b14d83663dc508aa16607a5efb,0x0e22fafbcae714df93561f55ce0ec547c98ae23e0f58a0e4cd5fe157edca1c4f,0x1a405dfd689829d259c07d7962144343a2052edd73d8d805958c107d31d54860,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
//             node_types: [6,8,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
//             leaf_type:  0x04,
//             real_hash_path_len: 23
//         }
//     };
//     //let keccakCodeHash: [u8;32] =  [232,196,7,51,81,194,107,152,49,193,229,175,21,59,155,228,113,58,74,249,237,253,243,43,88,7,123,115,94,18,15,20];
//     let account_preimage = Account_preimage_excl_storage {
//         nonce_codesize_0:  0x0000000000000000000000000000000000000000000016ef0000000000000000,  //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[0]));
//         balance:0x0000000000000000000000000000000000000000000001395d857ace5efb1c6e,             //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[1]));
//         //storageRoot:0x098b50a409452b9e258d144cfe5f87e70c68cab71945db8f596b6447c811de51,         //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[2]));
//         //compressed_keccak_code_hash: poseidon2_domain(HASH_DOMAIN_BYTE32,split_byte32_to_fields(keccakCodeHash)),
//         compressed_keccak_code_hash:0x0b76dac2b0a40ec033204a8924a316feab1261917f1807c68dca97310bf17edb,
//         poseidon_code_hash: 0x136a7980da529d9e8d3a71433fc9dc5aa8c01e3a4eb60cb3a4f9cf9ca5c8e0be, //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[4]));
        
//     };

//     // proving
//     let computed_root = storage_proof_on_mapping(user_address, slot, user_balance, padded_contract, hash_paths, account_preimage);
//     let state_root = 0x166065fc76a540ec1ec944e4a8e409c8d9615b77621504efff154e0132f8e8f8;
//     assert(computed_root == state_root, "computed_root doesnt match storage root");
// }

// #[test]
// fn test_get_state_root() {
//     let header_rlp:[u8;607] = [249,2,92,160,239,37,169,176,180,227,63,164,8,23,74,123,2,50,96,72,192,223,169,179,175,31,225,216,123,74,73,232,114,130,59,90,160,29,204,77,232,222,199,93,122,171,133,181,103,182,204,212,26,211,18,69,27,148,138,116,19,240,161,66,253,64,212,147,71,148,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,160,22,96,101,252,118,165,64,236,30,201,68,228,168,228,9,200,217,97,91,119,98,21,4,239,255,21,78,1,50,248,232,248,160,136,102,42,69,64,99,89,76,135,191,116,65,216,161,127,113,49,212,190,59,37,30,139,65,60,85,44,161,45,226,246,216,160,158,25,2,237,43,125,57,186,32,212,200,246,195,128,119,200,198,67,196,165,185,217,54,244,106,106,21,249,173,46,18,143,185,1,0,0,2,16,0,4,0,0,64,0,0,32,0,0,128,64,32,0,4,0,0,34,0,32,16,8,16,18,0,0,80,1,1,5,16,0,0,32,2,8,0,16,0,128,0,0,0,0,0,0,0,64,0,0,32,2,4,0,0,0,4,0,32,0,0,0,0,128,0,4,112,32,0,2,0,0,8,0,0,0,0,0,0,8,16,0,0,0,0,160,1,0,0,0,0,0,8,0,0,0,0,66,16,0,16,0,0,4,0,0,0,8,8,0,0,0,64,32,16,64,0,0,0,0,16,0,0,2,0,0,1,4,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,64,0,0,0,8,129,128,0,0,0,0,7,65,2,64,130,0,0,1,32,0,64,0,16,0,0,0,0,0,32,0,2,0,32,64,0,16,0,0,0,0,0,0,0,32,32,0,0,34,0,0,0,32,0,0,128,2,1,0,64,0,0,20,0,0,32,0,0,8,0,0,0,16,0,0,32,0,128,16,0,132,0,0,0,2,0,0,4,0,0,2,4,0,0,0,0,32,17,0,128,0,0,0,32,0,12,0,0,0,2,131,98,190,31,131,152,150,128,131,14,199,206,132,102,104,97,14,184,97,216,131,5,3,32,132,103,101,116,104,136,103,111,49,46,50,48,46,49,133,108,105,110,117,120,0,0,0,0,0,0,0,98,35,151,26,49,19,62,111,213,69,22,123,70,156,179,46,68,8,66,169,246,237,189,150,167,155,212,142,202,153,105,118,50,142,15,6,182,252,51,82,55,245,167,10,219,154,87,83,247,147,198,131,202,118,201,93,24,196,4,87,170,156,181,215,1,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,136,0,0,0,0,0,0,0,0];
    
//     let state_root:Field = 0x166065fc76a540ec1ec944e4a8e409c8d9615b77621504efff154e0132f8e8f8;

//     let state_root_rlp = get_state_root(header_rlp);
//     assert(bytes32_to_field(state_root_rlp) == state_root, "state root doesnt match. Did the header layout change?");
// }
