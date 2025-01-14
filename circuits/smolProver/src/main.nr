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


global PADDED_CONTRACT_ADDRESS = [225,130,151,123,35,41,111,253,187,206,234,214,141,215,108,62,166,127,68,127,0,0,0,0,0,0,0,0,0,0,0,0];// 0xe182977b23296ffdbbceead68dd76c3ea67f447f000000000000000000000000
global BALANCES_SLOT = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
global PARTIAL_NULLIFIERS_SLOT = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6];
global COMPRESSED_KECCAK_CODE_HASH = 0x20005f9e60e77f484982af58de155585fb1ac65530a7d5a8418d6a5ad0bfab92;
global POSEIDON_CODE_HASH = 0x239851df34491459b1117506c3aa820ff5bc9829b7bb07dbee4498dc8ea9086e;


struct Storage_proof_data {
    hash_paths: Hash_paths_state_proof<MAX_HASH_PATH_SIZE,MAX_HASH_PATH_SIZE>,
    balance: Field,
    nonce_codesize_0: Field,
    header_rlp: [u8;MAX_RLP_SIZE],
    header_rlp_len: u32,
}

struct Contract_proof_data {
    balance: Field,
    nonce_codesize_0: Field,
    header_rlp: [u8;MAX_RLP_SIZE],
    header_rlp_len: u32,
}

fn get_burn_address(secret: Field) -> [u8;32] {
    let hash:[u8] = poseidon::bn254::hash_1([secret]).to_be_bytes(32);//.as_array();
    let mut burn_address:[u8;32] = [0;32];

    // replace last 12 bytes with zero since address is only 20 bytes (noir doesnt support a nicer method hence whacky for loop)
    for index in 0 .. 20 {
        burn_address[index+12] = hash[index];   
    }
    burn_address
}

// nonce makes sure the hash is never the same even when the amount is different
// secret is so others cant try and find the pre-image (since this hash is posted onchain)
fn hash_nullifier(amount: Field, nonce:Field, secret: Field) -> Field {
    poseidon::bn254::hash_3([amount,nonce,secret])
}

// nonce makes sure the hash is never the same even when the amount is different
// secret is so others cant try and find the pre-image (since this hash is posted onchain)
fn hash_nullifier_id(nonce:Field, secret: Field) -> Field {
    poseidon::bn254::hash_2([nonce,secret])
}

//TODO check if its okay id prevNullifier id maps to a nullfier which is 0x000000000
fn main(
        //----- public inputs
        remint_address:pub Field, // the address to re-mint to
        withdraw_amount: pub Field,
        nullifier: pub Field,
        nullifier_id:pub Field,
        block_hash:pub [u8;32], 
        
        //-----very privacy sensitive data -----
        secret: Field, //burnaddress is derived from secret // TODO instead of using a secrets use public cryptography shit so hardware wallets dont have to create a whole ass proof. Also makes complexity lower for hot wallets to ensure safety and better compatability with metamasksnap.
        burned_balance: [u8;32],  //TODO split into fields constraint golf or just as a field (also gas golf) (assumes a balance never > FIELD_LIMIT)
        nonce: Field, // nonce to create a nulliefier from to track encrypted spend_amounts
        prev_nullifier_id: Field, // just here for the storage proof of prev_nullifier, since prev_nullifier already contains all info
        prev_spend_amount: Field,
        burn_addr_storage_proof: Hash_paths_state_proof<MAX_HASH_PATH_SIZE,MAX_HASH_PATH_SIZE>,
        prev_nullifier_storage_proof: Hash_paths_state_proof<MAX_HASH_PATH_SIZE,MAX_HASH_PATH_SIZE>,
        
        // ---- insensitive data (is private to reduce gas) --
        contract_data: Contract_proof_data
    ) {
    // to prevent the proof being stolen from the mempool and used for a differen withdraw address
    // TODO check if you realy need to do this? Tornadocash something similair tho.
    assert(remint_address != 0x0);

    //------------- check state root is in blockhash ----------------
    let state_root_rlp = get_state_root(contract_data.header_rlp);
    let computed_block_hash:[u8;32] = keccak256(contract_data.header_rlp,contract_data.header_rlp_len);
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
    assert(bytes32_to_field(state_root_rlp) == state_root_burn_addr, "computed state root from the burn address merkle proof doesnt match the one from the block header rlp"); 
    
    //--------prev nullifier------------
    if (nonce != 0) {
        // verify that the nullifier exist onchain with a storage proof
        // cant do this outside the circuit since that links prev_nullifier_id with the nullifier_id
        let prev_nullifier: [u8;32] = hash_nullifier(prev_spend_amount,nonce-1,secret).to_be_bytes(32).as_array();
        
        let state_root_prev_nullifier_id = storage_proof_on_mapping(
            prev_nullifier_id.to_be_bytes(32).as_array(), 
            PARTIAL_NULLIFIERS_SLOT, 
            prev_nullifier, 
            PADDED_CONTRACT_ADDRESS, 
            prev_nullifier_storage_proof, 
            contract_account_preimage
        );

        assert(bytes32_to_field(state_root_rlp) == state_root_prev_nullifier_id, "computed state root from the prev_nullifier_id merkle proof doesnt match the one from the block header rlp");
        
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
    std::field::bn254::assert_lt(new_spend_amount,bytes32_to_field(burned_balance));
    let computed_nullifier: Field = hash_nullifier(new_spend_amount,nonce,secret);
    assert(computed_nullifier == nullifier, "public input: nullifier, doesnt match the one computed in the circuit");

    // ----- nullifier_id -------------
    let computed_nullifier_id = hash_nullifier_id(nonce,secret);
    assert(computed_nullifier_id == nullifier_id, "computed nullifier doesnt match provided nullifier");
}

#[test]
fn test_hashing() {
    let nonce = 0;
    let secret = 123;
    let address = get_burn_address(secret);
    let nullifier = hash_nullifier_id(nonce,secret);
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

// #[test]
// fn test_main() {
//     let storage_proof_data = Storage_proof_data {
//         hash_paths :Hash_paths_state_proof{
//                 account_proof: Hash_path_proof {
//                 hash_path:  [0x18b1fe2e618964832b16eefb136251cd39a63a687d80f2a2560854cebc856f06,0x29971c370474d611571b92ce775453c90cd790eb80e6d2ee8686bb6a461f9ec4,0x1be77536c5e75c70004c9b21d1992487efb258465018d58b83fd55023c6359c9,0x0713cac09aa547f2492201586c7a505fcc71ab244b629a418ae480c2d77cfd36,0x148c752c025eba6c7b5b78a18518fce61b5dc4a9f88f41db22e1cb1d75be0038,0x22238e4911b59dd246116cac362354f5948c065d77f35fe24f2f7cae2d5bf312,0x03e21c3745fb4a5c9b3cde94b26412fa705ca12ae940e679882dea95a0969555,0x0d9439e1b12f727eb0643208106c0b9918768f7107225c8832956e6aeec84cd3,0x292ffa2cc602b53aed3dd09c36b41722cf43066826a1f24dd9afb6fbbbfe1274,0x00f1864a0a0dd276d0f4a9df75142fbdac5b3b7d97b276efe2a6153896d89f99,0x078e449e13b53f84e148fff306253f4fe2264c4a26be5c349fcbf9bb7db21ca3,0x25cffbefdc352d6a252d5160011027fa41212620d86311a9be30e27268604fb7,0x06f7c308c13e32251910b3ab7abcf73b0d35d2ace7e19335845e0df0cb871e04,0x12b927705a5d8ed2083bc899231d85c3f7928ad5aa33c5fdbd59b9b658e7bfbe,0x2d537fbf885bfb7867fcae6cb3cfb03a472a5c490f1e268d8843dccd183c2ff3,0x0a1fdc15bb3ed98c332ed314aa7f009ccc4c25c68533d6cd1eae8dc2525bf0f6,0x09843928cac270f8388e42fa5fa208ae6a34d0fc255821fb5547dfebd7d06c9e,0x00c9db5556c821db50b167f91f9566d3fc06c29b0fd72dbc92f127d8df968a8d,0x2300e52b80920f0c876ac004820496bf40a1850ddd048d4e172cc63d18f6a700,0x073128402c012f6f9a42133089182eef82fd29730ddb3b1e1a6ce84d2cdd08c6,0x048dd2df00f46b3072e5470665b23a7e0342eab65dcfd13b5b814cd1a18d6c47,0x26832cf479df6416ca4d5c759cc5587968ec611377bf36d295e692df90802a7d,0x000aeced564af3dc5062d6919fa946e9559b1d6648bce699cdfc44935a04e6de,0,0,0],
//                 leaf_type: 4,
//                 node_types: [6,8,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,0,0,0],
//                 real_hash_path_len: 23,
//                 hash_path_bools: [true,false,true,true,true,true,false,true,false,true,true,true,true,false,false,true,true,true,false,false,true,false,false,false,false,false]
//             },
//             storage_proof: Hash_path_proof {
//                 hash_path: [0x245d054b6d8471d2e8e0f62d283be9b83988dc6fdbf7cc37b17d2d93eff30f0a,0x2515e9e12e7945615459d9d265ec1db1c5a6eaeb76bfe41cd56667bce5995a1e,0x1ea3fa35506a57ba9a6c80970598eac13df9bb8affe080beeb2212c7736751ab,0x1587e78a8555da1444c3929bfbd35f36ff81836d1bebb7a2197e03a380818bab,0x1219e073f19a17e378dc85b9d149a2524ebc2590c7ad64eca63abbdfaf4085b0,0x1e85ff396be0bd86e0552d3d870ed5189291b69b185c20baf4c13df23621c4f5,0x1740ff8e94a131926a28c8b57df6945e67017aabec6741885e3a3ae6225a15b2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
//                 leaf_type: 4,
//                 node_types: [7,9,9,9,9,9,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
//                 real_hash_path_len: 7,
//                 hash_path_bools: [false,false,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false]
//             },
//         },
//             contract_balance: 0,
//             header_rlp:[249,2,97,160,100,218,207,185,183,74,175,7,223,243,175,10,210,120,1,225,104,153,84,246,58,129,237,15,175,158,247,223,178,244,171,151,160,29,204,77,232,222,199,93,122,171,133,181,103,182,204,212,26,211,18,69,27,148,138,116,19,240,161,66,253,64,212,147,71,148,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,160,31,141,188,137,168,231,105,55,132,83,134,35,153,86,93,249,43,8,186,140,146,179,103,46,212,243,214,248,140,182,177,6,160,4,41,153,203,145,153,0,77,13,43,214,88,214,39,171,94,95,142,117,58,134,119,104,174,193,140,209,94,46,57,188,76,160,153,195,150,134,240,183,232,68,193,14,10,228,110,190,135,178,107,55,136,19,79,1,161,163,39,10,58,69,56,204,168,16,185,1,0,0,0,0,0,0,0,0,0,0,0,0,0,16,0,0,0,0,0,0,131,0,0,0,0,0,64,1,0,0,0,0,0,0,0,2,0,0,0,0,0,8,0,1,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0,2,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0,64,0,0,0,0,0,0,0,128,0,2,0,0,0,0,0,4,0,2,2,8,0,0,0,0,0,0,4,0,0,0,0,2,32,0,0,0,0,16,64,0,32,0,0,0,0,0,0,0,64,0,0,0,0,0,0,64,0,0,0,0,0,16,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,2,0,32,0,0,0,0,0,0,0,4,0,0,0,8,0,0,0,0,17,0,0,0,0,0,0,1,0,64,1,0,1,2,1,32,0,0,0,18,0,0,128,0,0,32,0,0,0,0,128,0,4,0,0,0,0,0,0,0,0,144,2,0,0,0,0,64,0,0,0,0,0,32,0,0,0,1,0,2,131,118,230,248,131,152,150,128,131,4,153,239,132,103,126,15,16,184,97,216,131,5,8,0,132,103,101,116,104,136,103,111,49,46,50,49,46,49,133,108,105,110,117,120,0,0,0,0,0,0,0,102,37,209,111,27,248,56,127,219,164,66,220,123,1,220,109,100,51,237,102,226,5,9,93,182,184,215,7,94,23,143,133,3,57,122,59,186,51,69,197,243,192,144,20,223,92,113,209,162,17,79,147,214,99,19,198,207,148,188,73,239,37,131,225,1,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,136,0,0,0,0,0,0,0,0,132,2,164,70,50,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
//             header_rlp_len:612,
//             nonce_codesize_0:0x000000000000000000000000000000000000000000000fa40000000000000001,
//         };


//     let secret = 4578177650514904301890689815070162741555432086518939118332334535479016943032;

//     let remint_address = 0x794464c8c91A2bE4aDdAbfdB82b6db7B1Bb1DBC7;
//     let burned_balance = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,22,196,171,190,190,160,16,0,0];
//     let block_hash =  [64,245,48,30,62,193,185,1,21,193,237,117,214,241,229,120,212,66,118,122,6,60,35,105,193,15,30,26,39,184,115,129];
//     let nullifier = hash_nullifier(secret);
//     main(remint_address,burned_balance,block_hash,nullifier,secret,storage_proof_data);
// }
