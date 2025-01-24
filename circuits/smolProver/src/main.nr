use dep::ScrollStorageProver::{mapping_slot_to_blockhash, get_state_root};
use dep::ScrollStorageProver::{Hash_path_proof, Hash_paths_state_proof, Account_preimage_excl_storage};
use dep::std::field::bytes32_to_field;
use dep::std::hash::poseidon;
use dep::std::hash::keccak256;

// 54 is the highest value that still run in noirjs wasm
// might be enough since it can support scroll up to 18014398 billion account and for the contract to have 18014398 billion different slots
// splitting the proof up into account, storage proof seperately could increase the depth to 108 which would be 324518553000000000000 billion slots

// MAX_HASH_PATH_SIZE can be up to 32 to be proven in the browser. 248 to cover the full tree
// the account tree depth of sepolia is 23
global MAX_HASH_PATH_SIZE: u32 = 23; //248;//32; //this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
global MAX_RLP_SIZE: u32 = 650; //1000; //should be enough scroll mainnet wasn't going above 621, my guess is 673 bytes max + rlp over head. idk what overhead is tho.
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
    burn_addr_state_proof: Hash_paths_state_proof<MAX_HASH_PATH_SIZE,MAX_HASH_PATH_SIZE>,
    prev_nullifier_state_proof: Hash_paths_state_proof<MAX_HASH_PATH_SIZE,MAX_HASH_PATH_SIZE>,
    // ---- insensitive data (is private to reduce gas) --
    contract_data: Contract_proof_data<MAX_RLP_SIZE>
) {
    // to prevent the proof being stolen from the mempool and used for a differen withdraw address
    // TODO check if you realy need to do this? Tornadocash something similair tho.
    assert(remint_address != 0x0);

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
    let blockhash_burn_addr = mapping_slot_to_blockhash(
        burn_address,
        burned_balance,
        BALANCES_SLOT,
        burn_addr_state_proof.storage_proof,
        burn_addr_state_proof.account_proof,
        PADDED_CONTRACT_ADDRESS,
        contract_account_preimage,
        contract_data.header_rlp,
        contract_data.header_rlp_len
    );
    assert(blockhash_burn_addr == block_hash, "given block hash doesnt match computed block hash from the burn_address proof");

    //--------prev nullifier------------
    if (nonce != 0) {
        // verify that the nullifier exist onchain with a storage proof
        // cant do this outside the circuit since that links prev_nullifier_id with the nullifier_id
        let prev_nullifier: [u8;32] = hash_nullifier(prev_spend_amount, nonce - 1, secret).to_be_bytes();

        let blockhash_prev_nullifier_id = mapping_slot_to_blockhash(
            prev_nullifier_id.to_be_bytes(),
            prev_nullifier,
            PARTIAL_NULLIFIERS_SLOT,
            prev_nullifier_state_proof.storage_proof,
            prev_nullifier_state_proof.account_proof,
            PADDED_CONTRACT_ADDRESS,
            contract_account_preimage,
            contract_data.header_rlp,
            contract_data.header_rlp_len
        );

        assert(blockhash_prev_nullifier_id == block_hash, "given block hash doesnt match computed block hash from the prev_nullifier proof");
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

#[test]
fn test_hashing() {
    let nonce = 0;
    let secret = 123;
    let address = get_burn_address(secret);
    let nullifier = hash_nullifier_id(nonce, secret);
    println(address);
    println(nullifier);
}

#[test]
fn test_get_state_root() {
    let header_rlp:[u8;607] = [
        249, 2, 92, 160, 239, 37, 169, 176, 180, 227, 63, 164, 8, 23, 74, 123, 2, 50, 96, 72, 192, 223, 169, 179, 175, 31, 225, 216, 123, 74, 73, 232, 114, 130, 59, 90, 160, 29, 204, 77, 232, 222, 199, 93, 122, 171, 133, 181, 103, 182, 204, 212, 26, 211, 18, 69, 27, 148, 138, 116, 19, 240, 161, 66, 253, 64, 212, 147, 71, 148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 22, 96, 101, 252, 118, 165, 64, 236, 30, 201, 68, 228, 168, 228, 9, 200, 217, 97, 91, 119, 98, 21, 4, 239, 255, 21, 78, 1, 50, 248, 232, 248, 160, 136, 102, 42, 69, 64, 99, 89, 76, 135, 191, 116, 65, 216, 161, 127, 113, 49, 212, 190, 59, 37, 30, 139, 65, 60, 85, 44, 161, 45, 226, 246, 216, 160, 158, 25, 2, 237, 43, 125, 57, 186, 32, 212, 200, 246, 195, 128, 119, 200, 198, 67, 196, 165, 185, 217, 54, 244, 106, 106, 21, 249, 173, 46, 18, 143, 185, 1, 0, 0, 2, 16, 0, 4, 0, 0, 64, 0, 0, 32, 0, 0, 128, 64, 32, 0, 4, 0, 0, 34, 0, 32, 16, 8, 16, 18, 0, 0, 80, 1, 1, 5, 16, 0, 0, 32, 2, 8, 0, 16, 0, 128, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 32, 2, 4, 0, 0, 0, 4, 0, 32, 0, 0, 0, 0, 128, 0, 4, 112, 32, 0, 2, 0, 0, 8, 0, 0, 0, 0, 0, 0, 8, 16, 0, 0, 0, 0, 160, 1, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 66, 16, 0, 16, 0, 0, 4, 0, 0, 0, 8, 8, 0, 0, 0, 64, 32, 16, 64, 0, 0, 0, 0, 16, 0, 0, 2, 0, 0, 1, 4, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 8, 129, 128, 0, 0, 0, 0, 7, 65, 2, 64, 130, 0, 0, 1, 32, 0, 64, 0, 16, 0, 0, 0, 0, 0, 32, 0, 2, 0, 32, 64, 0, 16, 0, 0, 0, 0, 0, 0, 0, 32, 32, 0, 0, 34, 0, 0, 0, 32, 0, 0, 128, 2, 1, 0, 64, 0, 0, 20, 0, 0, 32, 0, 0, 8, 0, 0, 0, 16, 0, 0, 32, 0, 128, 16, 0, 132, 0, 0, 0, 2, 0, 0, 4, 0, 0, 2, 4, 0, 0, 0, 0, 32, 17, 0, 128, 0, 0, 0, 32, 0, 12, 0, 0, 0, 2, 131, 98, 190, 31, 131, 152, 150, 128, 131, 14, 199, 206, 132, 102, 104, 97, 14, 184, 97, 216, 131, 5, 3, 32, 132, 103, 101, 116, 104, 136, 103, 111, 49, 46, 50, 48, 46, 49, 133, 108, 105, 110, 117, 120, 0, 0, 0, 0, 0, 0, 0, 98, 35, 151, 26, 49, 19, 62, 111, 213, 69, 22, 123, 70, 156, 179, 46, 68, 8, 66, 169, 246, 237, 189, 150, 167, 155, 212, 142, 202, 153, 105, 118, 50, 142, 15, 6, 182, 252, 51, 82, 55, 245, 167, 10, 219, 154, 87, 83, 247, 147, 198, 131, 202, 118, 201, 93, 24, 196, 4, 87, 170, 156, 181, 215, 1, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 0, 0, 0, 0, 0, 0, 0, 0
    ];

    let state_root:Field = 0x166065fc76a540ec1ec944e4a8e409c8d9615b77621504efff154e0132f8e8f8;

    let state_root_rlp = get_state_root(header_rlp);
    assert(
        bytes32_to_field(state_root_rlp) == state_root, "state root doesnt match. Did the header layout change?"
    );
}

#[test]
fn test_main() {
    //----- public inputs
    let remint_address: Field = 0x93211e420c8F552a0e4836f84892a0D4eb5D6D54;
    let withdraw_amount:  Field = 0x8ac7230489e80000;
    let nullifier: Field = 0x212456bab521c4afa65cca2751d74f7cbac9ba747d7bc3c21be994b886a7bfe1;
    let nullifier_id: Field = 0x0a2fdf0860adb5ea719794ecf7ec81cc57e56f1846e1508a7fa6448d36cd9624;
    let block_hash: [u8; 32] = [0x40,0x60,0xee,0xf3,0xb5,0xa5,0xf2,0x87,0x02,0x74,0xb0,0x30,0xe8,0xd8,0x3c,0x69,0xd2,0xf2,0x13,0xfe,0x4d,0x1b,0xd8,0x41,0xea,0x9b,0xe2,0x90,0x7f,0x79,0xc9,0x5d];
    
    //-----private inputs -----
    let secret: Field  = 0x1cf2c2021c2e15a1c61547a32a6295078aacf089edb3cc66fd992f627f30f824;
    let burned_balance: [u8; 32]  = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x16,0xc4,0xab,0xbe,0xbe,0xa0,0x10,0x00,0x00];
    let nonce: Field = 3;
    let prev_nullifier_id: Field = 0x1546f8d229c5a0943586cd5261ab4adbf995e849976a689a6055a32d4fae8337;
    let prev_spend_amount: Field = 30000000000000000000;

    let burn_addr_storage_proof = Hash_paths_state_proof {
        storage_proof: Hash_path_proof {
            hash_path:  [0x271dcf322b72eadde439e5f2fe303af0d6ab3fa6c79a9466704a4791f85af7b3,0x0000000000000000000000000000000000000000000000000000000000000000,0x2bff2dd5919b91b80722debba0da0ba15eb2ac950ba965c07cde492494242177,0x29e2f4c47f71ee542e6ab5571f0eda8230b57f3166178244ea0603655ec82ddb,0x037babdabb3dd50298f663dcfb1124a68a0f2b80dcd4a949f797a188e6c93964,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            node_types: [7,8,9,9,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            leaf_type:  0x04,
            real_hash_path_len: 5,
            hash_path_bools:  [false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false],
        },
        account_proof: Hash_path_proof {
            hash_path:  [0x0b2247fce447f1671dd6d174be45b074fd89a6330b08ab2c87496dee6f03115e,0x0000000000000000000000000000000000000000000000000000000000000000,0x2614c322fa1f971ce06d0c8fc2ab71bd13aac9e3a1bed9a69079a751275090e6,0x0103d17039f4bfb2134f878fddb08dc0f9919cc8177f195e2c21fd036d70e4d8,0x0bd0af6c5f4ac2609f47db7358b32af8707d9b1f1ea8816c43aaf088420c2a82,0x1876a6e0855526abd8bcbf767b7a467eadd99f56e18e89cc8f18e8d523621e65,0x17837b58b18c4fe6f293bb55920a56bf1733a70feed305e4ee807739d594d3b7,0x1e89d0ca62cf848177514f72239d630fc57864865dc889f656595d0dedcfe03c,0x24f5e254afbd2370fe36aab6d1a03f93c48f29a9cc60f56275a4a530f64f898f,0x245536539214afb67ba8c93f6f8bb5052b4d6c83468cfec754d137ae1cc7cec2,0x27ebaf0af037f48257d57cbfba74c0a006558633204390caacf3db1d5c65b07e,0x28f5020177be2ed30dddd260de462f2579c2d4bb122155124101bb8acf219a94,0x16a327dc5939dfd27bd90050baf91ee38546f140503161a0a754024837e09bb3,0x2d9d973280548b9501fbc42e50d14c6c09ed30087dbed6583edc5f72f9c9e3b3,0x1e38ae00c9d40824a4c6ea5c837a892ae1370c1ddb0b2f69f2334d67bdb4b1df,0x10fb06ec6d590d63efd1df5fee4e45e895c6c1e7d7c919522da0ed385139563f,0x1301413522e53da157c1757272fa2f1541b42d74eb6c010233b5f0e87ec40ed0,0x094cb1ae53b96f40b137c2dc5b659d6de3aae90e8f897882528dc509fef9acdf,0x2634dfe5f14fee94cd389e331c5a4492f50806970c524b2e56279de1bed5d93f,0x05d288c9cd54ee7b9cb7e1f1ae7e1ba224bc84462f6896af1672611c1a312014,0x1cdea36b73ebeb92696b6d7742cf491a3c80eb928170b995c3b36c82038535fb,0x16b46259455ce43f114a34d3b2e443994e4930aa944372351536d0c4f49c3ec1,0x14ccc4fe67292c6bf607664f80b0d4963e3ec3499178d736e2bad1b0626c6bee],
            node_types: [6,7,8,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],
            leaf_type:  0x04,
            real_hash_path_len: 23,
            hash_path_bools: [false,true,false,false,true,true,true,false,true,true,true,false,false,true,false,false,true,false,false,true,false,false,true],
        }
    };
    let prev_nullifier_state_proof = Hash_paths_state_proof {
        storage_proof: Hash_path_proof {
            hash_path:  [0x0b740b3b3c51a59c48c9eb1463d725ce7cac0bc306988485c1faab915d162544,0x1994aab20b7fed2fe15b917c4582250c146700553fefaf41449237bc67053b13,0x1792184d393ac7d787217a5704feca25054d79efa6d99dc0dac728234f2f5f7f,0x0e8a61ecf3189248e1aaa0c3fa333cc207b3b871c3b83621040e845bcc8fa7f3,0x1221df3235836747f28777f8eb3c78979ad8f4cb70c1d4bc63142116258d60b8,0x22766d6b32b905252b05efb58814689ccc270cf5b526e9779ec552a279ff8cd5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            node_types: [6,9,7,9,9,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            leaf_type:  0x04,
            real_hash_path_len: 6,
            hash_path_bools:  [false,false,true,false,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false],
        },
        account_proof: Hash_path_proof {
            hash_path:  [0x0b2247fce447f1671dd6d174be45b074fd89a6330b08ab2c87496dee6f03115e,0x0000000000000000000000000000000000000000000000000000000000000000,0x2614c322fa1f971ce06d0c8fc2ab71bd13aac9e3a1bed9a69079a751275090e6,0x0103d17039f4bfb2134f878fddb08dc0f9919cc8177f195e2c21fd036d70e4d8,0x0bd0af6c5f4ac2609f47db7358b32af8707d9b1f1ea8816c43aaf088420c2a82,0x1876a6e0855526abd8bcbf767b7a467eadd99f56e18e89cc8f18e8d523621e65,0x17837b58b18c4fe6f293bb55920a56bf1733a70feed305e4ee807739d594d3b7,0x1e89d0ca62cf848177514f72239d630fc57864865dc889f656595d0dedcfe03c,0x24f5e254afbd2370fe36aab6d1a03f93c48f29a9cc60f56275a4a530f64f898f,0x245536539214afb67ba8c93f6f8bb5052b4d6c83468cfec754d137ae1cc7cec2,0x27ebaf0af037f48257d57cbfba74c0a006558633204390caacf3db1d5c65b07e,0x28f5020177be2ed30dddd260de462f2579c2d4bb122155124101bb8acf219a94,0x16a327dc5939dfd27bd90050baf91ee38546f140503161a0a754024837e09bb3,0x2d9d973280548b9501fbc42e50d14c6c09ed30087dbed6583edc5f72f9c9e3b3,0x1e38ae00c9d40824a4c6ea5c837a892ae1370c1ddb0b2f69f2334d67bdb4b1df,0x10fb06ec6d590d63efd1df5fee4e45e895c6c1e7d7c919522da0ed385139563f,0x1301413522e53da157c1757272fa2f1541b42d74eb6c010233b5f0e87ec40ed0,0x094cb1ae53b96f40b137c2dc5b659d6de3aae90e8f897882528dc509fef9acdf,0x2634dfe5f14fee94cd389e331c5a4492f50806970c524b2e56279de1bed5d93f,0x05d288c9cd54ee7b9cb7e1f1ae7e1ba224bc84462f6896af1672611c1a312014,0x1cdea36b73ebeb92696b6d7742cf491a3c80eb928170b995c3b36c82038535fb,0x16b46259455ce43f114a34d3b2e443994e4930aa944372351536d0c4f49c3ec1,0x14ccc4fe67292c6bf607664f80b0d4963e3ec3499178d736e2bad1b0626c6bee],
            node_types: [6,7,8,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],
            leaf_type:  0x04,
            real_hash_path_len: 23,
            hash_path_bools:  [false,true,false,false,true,true,true,false,true,true,true,false,false,true,false,false,true,false,false,true,false,false,true],
        }
    };
    let contract_data = Contract_proof_data {
        balance: 0,
        nonce_codesize_0: 0x0000000000000000000000000000000000000000000010140000000000000001,
        header_rlp: [0xf9,0x02,0x60,0xa0,0xa3,0x46,0x01,0x73,0x6f,0x2c,0xd1,0x19,0xdc,0x0a,0x00,0x89,0x1e,0x66,0x98,0x3f,0xff,0xbc,0x53,0x02,0xdb,0x38,0x48,0x19,0x08,0x37,0x52,0x10,0xb9,0x45,0x29,0x15,0xa0,0x1d,0xcc,0x4d,0xe8,0xde,0xc7,0x5d,0x7a,0xab,0x85,0xb5,0x67,0xb6,0xcc,0xd4,0x1a,0xd3,0x12,0x45,0x1b,0x94,0x8a,0x74,0x13,0xf0,0xa1,0x42,0xfd,0x40,0xd4,0x93,0x47,0x94,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xa0,0x09,0x26,0xc1,0x03,0x38,0x05,0x97,0xaf,0x23,0xf3,0x26,0x22,0x54,0xf3,0xfd,0xf8,0x33,0x12,0xef,0xa6,0xca,0x5c,0xba,0x62,0xab,0x99,0x29,0x4b,0x1f,0x00,0xeb,0xc1,0xa0,0xfd,0x94,0xfc,0xc1,0x2e,0x03,0xd5,0x9d,0xa6,0x01,0xc3,0x02,0x29,0x27,0x26,0xd6,0xb5,0x5c,0x0f,0xf0,0xcc,0xc3,0x15,0x6c,0x89,0x46,0x46,0x29,0xba,0x95,0xea,0xf2,0xa0,0x11,0x37,0x9e,0x82,0x4b,0x70,0xf6,0x1c,0x78,0x16,0x29,0x67,0xf0,0xcb,0x4b,0x84,0xf5,0xf6,0xe8,0x84,0xc6,0x7e,0x57,0xd6,0xeb,0xfd,0xf7,0xb5,0xf3,0xd6,0x9c,0x59,0xb9,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x83,0x79,0x74,0xe5,0x83,0x98,0x96,0x80,0x82,0x96,0x7e,0x84,0x67,0x90,0xfe,0xbb,0xb8,0x61,0xd8,0x83,0x05,0x08,0x00,0x84,0x67,0x65,0x74,0x68,0x88,0x67,0x6f,0x31,0x2e,0x32,0x31,0x2e,0x31,0x85,0x6c,0x69,0x6e,0x75,0x78,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x9c,0x39,0x1b,0x5e,0x2d,0x8f,0x2e,0x03,0x0a,0x85,0xd0,0xcf,0x96,0x2a,0x0b,0xed,0x77,0x03,0xc2,0xda,0x0b,0xc0,0x1b,0x2c,0x3e,0x88,0x6a,0xfd,0x24,0x78,0x80,0xb8,0x1c,0xa0,0xac,0x28,0xc4,0xfd,0xc4,0x5f,0xbf,0x08,0xa9,0x5b,0x18,0xad,0xae,0x36,0x18,0xe1,0x28,0x41,0xf0,0x59,0xfe,0x4c,0x13,0xa5,0xa6,0x3a,0xe8,0x8a,0x28,0x04,0x01,0xa0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x88,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x84,0x02,0x8a,0xcc,0x15,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
        header_rlp_len: 611,
    };

    main(
        //----- public inputs
        remint_address,
        withdraw_amount,
        nullifier,
        nullifier_id,
        block_hash,
        //-----private inputs -----
        secret,
        burned_balance,
        nonce,
        prev_nullifier_id,
        prev_spend_amount,
        burn_addr_storage_proof,
        prev_nullifier_state_proof,
        contract_data,
    );
}


