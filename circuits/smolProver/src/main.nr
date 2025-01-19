use dep::ScrollStorageProver::{storage_proof_on_mapping, get_state_root};
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

global PADDED_CONTRACT_ADDRESS: [u8;32] = [12,2,201,72,143,97,145,230,227,97,139,60,144,120,137,84,238,246,185,130,0,0,0,0,0,0,0,0,0,0,0,0];// 0x0c02c9488f6191e6e3618b3c90788954eef6b982000000000000000000000000
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
    std::field::bn254::assert_lt(new_spend_amount, bytes32_to_field(burned_balance));
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
    let withdraw_amount:  Field = 0x11f403e671df5c7fff;
    let nullifier: Field = 0x2f24bc021d72eb09ad577ca1f15bec70045c7f30d921b2af2030c72e9d23c552;
    let nullifier_id: Field = 0x1c1e7be1d4b9836802c551f5c1ac559c7eddeaff2e70d73e54fba5eaac5689f1;
    let block_hash: [u8; 32] = [0x6c,0xad,0xb2,0xa1,0x7a,0x9b,0xb9,0x69,0x29,0x77,0xe8,0x28,0x4c,0xdb,0x13,0x74,0x62,0xe4,0xde,0xc8,0xfa,0xed,0x6c,0xd0,0x68,0x8c,0x8d,0x79,0x09,0xbd,0x32,0x1f];
    
    //-----private inputs -----
    let secret: Field  = 0x1cf2c2021c2e15a1c61547a32a6295078aacf089edb3cc66fd992f627f30f824;
    let burned_balance: [u8; 32]  = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x16,0xc4,0xab,0xbe,0xbe,0xa0,0x10,0x00,0x00];
    let nonce: Field = 0;
    let prev_nullifier_id: Field = 0x07db882ac66d64b2f0bfa84958e613c63a96a66a2b7e6d762f6f32ae62a908b7;
    let prev_spend_amount: Field = 0;

    let burn_addr_storage_proof = Hash_paths_state_proof {
        storage_proof: Hash_path_proof {
            hash_path:  [0x2664a4f45d7b512e6bfc70507255cf7300082fea39883e4a92a7a2057068240e,0x0000000000000000000000000000000000000000000000000000000000000000,0x1d2c9037d0cd45a3677619b90f6f0c0be89f0aedcf3a911cf75f06bf3e149d89,0x0000000000000000000000000000000000000000000000000000000000000000,0x24f7dcd2c6ea0396d6c7c2afe0a0d2b5ab03fbba920b16545dfa241a1b73ae91,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            node_types: [6,8,8,8,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            leaf_type:  0x04,
            real_hash_path_len: 5,
            hash_path_bools:  [false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false],
        },
        account_proof: Hash_path_proof {
            hash_path:  [0x17b5b341c4302f591b34847f07687ef2bacf846125694380e808452236d6fded,0x020d98b6007e3fd2f6c00e7fd9fa431c189319dccda949f76cedded67a4d1d2b,0x0000000000000000000000000000000000000000000000000000000000000000,0x2f6229ff0c3dce0ed77d03dce60e49c31b571d49e29534f5fb915c80f054c533,0x145cf3f613bb859fede45ab3294e8e1fbb74c169c19329a5acc24c6175485f0b,0x249a7969a5ad587ec2893adf50708ff232e5ff772bcfab7f5b48e9c98ada3cb4,0x1febe3f7abd3eb019bf18352d6ba9be1a72105b00f3ff9643784a8b5f20a2a81,0x2bcc3266fde4a4a970f79e5280920daa0c452f3a27031cee20b8b6ad0a77b879,0x21ac9372b735c63f9a9746d08505608b071dc512146152ba815ae0c3fbfc270f,0x134c862f6127f86766b08cdb1158ff9546d88eb6bac9d1a85da3754751f9eb65,0x14a03077d67dfcee90d8d90ead334a4dafc5a1af6d3771faaf44025fc28c07c2,0x06e91e9f010f7544074a60eee55ecbdcfa489b32d3697a6cb4d03c6c5307891b,0x2094f8aa6f98eb097017c9b7069fd4c4b753441ae403d0c04e2373e5ef273b59,0x2d1cbdb480afa6e3302cb05f191cf5f6f72ecd79ea6fcf018acb44f6770ee1d9,0x027fec991c32a71565c4864663e13666036e3a58f097209fde61371b0fbf0856,0x0767c04b099fd56191928e64692f90e6301a9da4283f57242bb909d2fb9fbc2f,0x2d7a6c2917a449497527dc8f9ee07b99223c1d6c4cae7ec993e3d96e0a95d893,0x27678b63575a9f524c51a7fffc2eff2527b1397ec81b9aa38e17e66b3bb06e3d,0x08530c0a3ab96631ff11f5bc5e3343fd04fe871f2cd88f58985ab4dae09ad64e,0x1fbe2267f893b95ce85d9a001f9d2bca301ef81a9ea3ac822798f7fff20e1e48,0x1624aa8e20f03335d2494777c2ca684a8ee1beed7e44995238e38c25897d053b,0,0],
            node_types: [6,7,7,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,0,0],
            leaf_type:  0x04,
            real_hash_path_len: 21,
            hash_path_bools: [false,true,true,true,true,true,true,true,true,false,true,false,true,true,false,false,false,false,true,true,true,false,false],
        }
    };
    let prev_nullifier_storage_proof = Hash_paths_state_proof {
        storage_proof: Hash_path_proof {
            hash_path:  [0x1c515feb0658f1efbae50618c71033004646163d9a2a5259104c8f128b58b8df,0x074dd605c748a1733c3c3b34591753d32c064c77acb3de3013438d356606e181,0x17c9fd382c988682472de53868071a3bd563ce0c63004508b2c0b509c4f08096,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            node_types: [7,7,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            leaf_type:  0x04,
            real_hash_path_len: 3,
            hash_path_bools:  [false,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false],
        },
        account_proof: Hash_path_proof {
            hash_path:  [0x17b5b341c4302f591b34847f07687ef2bacf846125694380e808452236d6fded,0x020d98b6007e3fd2f6c00e7fd9fa431c189319dccda949f76cedded67a4d1d2b,0x0000000000000000000000000000000000000000000000000000000000000000,0x2f6229ff0c3dce0ed77d03dce60e49c31b571d49e29534f5fb915c80f054c533,0x145cf3f613bb859fede45ab3294e8e1fbb74c169c19329a5acc24c6175485f0b,0x249a7969a5ad587ec2893adf50708ff232e5ff772bcfab7f5b48e9c98ada3cb4,0x1febe3f7abd3eb019bf18352d6ba9be1a72105b00f3ff9643784a8b5f20a2a81,0x2bcc3266fde4a4a970f79e5280920daa0c452f3a27031cee20b8b6ad0a77b879,0x21ac9372b735c63f9a9746d08505608b071dc512146152ba815ae0c3fbfc270f,0x134c862f6127f86766b08cdb1158ff9546d88eb6bac9d1a85da3754751f9eb65,0x14a03077d67dfcee90d8d90ead334a4dafc5a1af6d3771faaf44025fc28c07c2,0x06e91e9f010f7544074a60eee55ecbdcfa489b32d3697a6cb4d03c6c5307891b,0x2094f8aa6f98eb097017c9b7069fd4c4b753441ae403d0c04e2373e5ef273b59,0x2d1cbdb480afa6e3302cb05f191cf5f6f72ecd79ea6fcf018acb44f6770ee1d9,0x027fec991c32a71565c4864663e13666036e3a58f097209fde61371b0fbf0856,0x0767c04b099fd56191928e64692f90e6301a9da4283f57242bb909d2fb9fbc2f,0x2d7a6c2917a449497527dc8f9ee07b99223c1d6c4cae7ec993e3d96e0a95d893,0x27678b63575a9f524c51a7fffc2eff2527b1397ec81b9aa38e17e66b3bb06e3d,0x08530c0a3ab96631ff11f5bc5e3343fd04fe871f2cd88f58985ab4dae09ad64e,0x1fbe2267f893b95ce85d9a001f9d2bca301ef81a9ea3ac822798f7fff20e1e48,0x1624aa8e20f03335d2494777c2ca684a8ee1beed7e44995238e38c25897d053b,0,0],
            node_types: [6,7,7,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,0,0],
            leaf_type:  0x04,
            real_hash_path_len: 21,
            hash_path_bools:  [false,true,true,true,true,true,true,true,true,false,true,false,true,true,false,false,false,false,true,true,true,false,false],
        }
    };
    let contract_data = Contract_proof_data {
        balance: 0,
        nonce_codesize_0: 0x0000000000000000000000000000000000000000000010110000000000000001,
        header_rlp: [0xf9,0x02,0x60,0xa0,0x63,0x32,0xba,0x36,0xbc,0x52,0x36,0x3b,0x4c,0x43,0x4a,0x64,0xea,0x1f,0xc0,0xf4,0x96,0x82,0x26,0x70,0x9f,0xa9,0x7f,0x0c,0xd1,0x58,0xba,0x6e,0xc0,0xef,0xaf,0x72,0xa0,0x1d,0xcc,0x4d,0xe8,0xde,0xc7,0x5d,0x7a,0xab,0x85,0xb5,0x67,0xb6,0xcc,0xd4,0x1a,0xd3,0x12,0x45,0x1b,0x94,0x8a,0x74,0x13,0xf0,0xa1,0x42,0xfd,0x40,0xd4,0x93,0x47,0x94,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xa0,0x29,0x0f,0x04,0x26,0x00,0xfe,0x14,0x79,0x6e,0xb5,0x8f,0x2c,0x1f,0xdd,0x1d,0x95,0xb4,0x12,0xe1,0x0d,0xe1,0x6b,0xe8,0x29,0x30,0x83,0x6d,0xa2,0xcf,0x87,0xd0,0xba,0xa0,0x38,0xe9,0xaf,0xaa,0x06,0xc1,0x51,0x9d,0x12,0x04,0xf0,0xb0,0xba,0xac,0x4b,0x25,0x0f,0xa7,0x29,0x1d,0x71,0x26,0xfe,0xda,0x56,0x23,0x8b,0x5d,0x6b,0x36,0xfa,0xc8,0xa0,0xc8,0xa7,0x2b,0x7d,0x87,0x3c,0xa0,0x33,0xdf,0xb0,0xab,0x74,0x2e,0x69,0xd6,0xaa,0x98,0x99,0x4f,0xfb,0x65,0x88,0xda,0xa7,0x4a,0x94,0x4b,0xa0,0x75,0xc3,0xed,0x71,0xb9,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x83,0x78,0x85,0x08,0x83,0x98,0x96,0x80,0x82,0x96,0x4e,0x84,0x67,0x8a,0x8f,0x06,0xb8,0x61,0xd8,0x83,0x05,0x08,0x00,0x84,0x67,0x65,0x74,0x68,0x88,0x67,0x6f,0x31,0x2e,0x32,0x31,0x2e,0x31,0x85,0x6c,0x69,0x6e,0x75,0x78,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x97,0xcf,0x99,0xc6,0x48,0x68,0xb0,0x6e,0x03,0xa2,0xf9,0x58,0x35,0xf8,0x75,0xd5,0x40,0xdd,0x0e,0x1e,0x55,0xde,0x7d,0xd4,0xec,0x50,0x2c,0xe3,0x04,0xaa,0xcb,0xd6,0x4d,0x45,0x46,0x60,0xe6,0x4a,0xb4,0xf6,0x55,0x7d,0xb8,0x0d,0x89,0xe7,0x8a,0xa6,0x7a,0x69,0x9d,0x20,0xd7,0x72,0xa7,0xe3,0xaf,0xe7,0x76,0x1a,0xb7,0x7e,0x12,0x1b,0x01,0xa0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x88,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x84,0x02,0x5b,0x4b,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
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
        prev_nullifier_storage_proof,
        contract_data,
    );
}
