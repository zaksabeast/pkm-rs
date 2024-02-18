use crate::reader::Reader;
use core::convert::TryInto;

// Thanks to PKHeX - https://github.com/kwsch/PKHeX/blob/4bb54334899cb2358b66bf97ba8d7f59c22430d7/PKHeX.Core/PKM/Util/PokeCrypto.cs

#[rustfmt::skip]
const BLOCK_POSITION: [usize; 128] = [
    0, 1, 2, 3,
    0, 1, 3, 2,
    0, 2, 1, 3,
    0, 3, 1, 2,
    0, 2, 3, 1,
    0, 3, 2, 1,
    1, 0, 2, 3,
    1, 0, 3, 2,
    2, 0, 1, 3,
    3, 0, 1, 2,
    2, 0, 3, 1,
    3, 0, 2, 1,
    1, 2, 0, 3,
    1, 3, 0, 2,
    2, 1, 0, 3,
    3, 1, 0, 2,
    2, 3, 0, 1,
    3, 2, 0, 1,
    1, 2, 3, 0,
    1, 3, 2, 0,
    2, 1, 3, 0,
    3, 1, 2, 0,
    2, 3, 1, 0,
    3, 2, 1, 0,

    // duplicates of 0-7 to eliminate modulus
    0, 1, 2, 3,
    0, 1, 3, 2,
    0, 2, 1, 3,
    0, 3, 1, 2,
    0, 2, 3, 1,
    0, 3, 2, 1,
    1, 0, 2, 3,
    1, 0, 3, 2,
];

#[rustfmt::skip]
const BLOCK_POSITION_INVERT: [usize; 32] =
[
    0, 1, 2, 4, 3, 5, 6, 7, 12, 18, 13, 19, 8, 10, 14, 20, 16, 22, 9, 11, 15, 21, 17, 23,
    0, 1, 2, 4, 3, 5, 6, 7, // duplicates of 0-7 to eliminate modulus
];

fn crypt_pkm<const STORED_SIZE: usize>(data: &[u8], mut seed: u32) -> [u8; STORED_SIZE] {
    let mut result = [0u8; STORED_SIZE];
    result.clone_from_slice(data);
    result.chunks_mut(2).skip(4).for_each(|bytes| {
        seed = 0x41c64e6du32.wrapping_mul(seed).wrapping_add(0x6073);
        bytes[0] ^= (seed >> 16) as u8;
        bytes[1] ^= (seed >> 24) as u8;
    });
    result
}

fn shuffle_array<const STORED_SIZE: usize, const BLOCK_SIZE: usize>(
    data: &[u8],
    sv: usize,
) -> [u8; STORED_SIZE] {
    let mut result = [0u8; STORED_SIZE];
    result[..8].copy_from_slice(&data[..8]);

    for block in 0..4 {
        let offset = BLOCK_POSITION[(sv * 4) + block];

        let source_start = 8 + (BLOCK_SIZE * offset);
        let dest_start = 8 + (BLOCK_SIZE * block);

        let source_block = &data[source_start..source_start + BLOCK_SIZE];
        let dest_block = &mut result[dest_start..dest_start + BLOCK_SIZE];

        dest_block.copy_from_slice(source_block);
    }

    result
}

pub(super) fn decrypt<const STORED_SIZE: usize, const BLOCK_SIZE: usize>(
    ekx: &[u8],
) -> [u8; STORED_SIZE] {
    let seed = ekx.read(0);
    let sv = ((seed as usize) >> 13) & 31;
    let pkx = crypt_pkm::<STORED_SIZE>(ekx, seed);
    shuffle_array::<STORED_SIZE, BLOCK_SIZE>(&pkx, sv)
}

pub(super) fn encrypt<const STORED_SIZE: usize, const BLOCK_SIZE: usize>(
    pkx: &[u8],
) -> [u8; STORED_SIZE] {
    let seed = pkx.read(0);
    let sv = ((seed as usize) >> 13) & 31;
    let shuffled = shuffle_array::<STORED_SIZE, BLOCK_SIZE>(pkx, BLOCK_POSITION_INVERT[sv]);
    crypt_pkm::<STORED_SIZE>(&shuffled, seed)
}

pub fn calculate_checksum(pkx: &[u8]) -> u16 {
    let mut checksum = 0u16;

    for chunks in pkx.chunks_exact(2) {
        let chunk = u16::from_le_bytes(chunks.try_into().unwrap());
        checksum = checksum.wrapping_add(chunk);
    }

    checksum
}
