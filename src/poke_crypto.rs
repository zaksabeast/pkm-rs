use crate::reader::Reader;
use core::{convert::TryInto, usize};

#[rustfmt::skip]
const BLOCK_SWAP_DST: [usize; 96] = [
    0, 1, 2,
    0, 1, 3,
    0, 2, 2,
    0, 3, 3,
    0, 2, 3,
    0, 3, 2,
    1, 1, 2,
    1, 1, 3,
    2, 2, 2,
    3, 3, 3,
    2, 2, 3,
    3, 3, 2,
    1, 2, 2,
    1, 3, 3,
    2, 1, 2,
    3, 1, 3,
    2, 3, 2,
    3, 2, 3,
    1, 2, 3,
    1, 3, 2,
    2, 1, 3,
    3, 1, 2,
    2, 3, 3,
    3, 2, 2,

    // duplicates of 0-7 to eliminate modulus
    0, 1, 2,
    0, 1, 3,
    0, 2, 2,
    0, 3, 3,
    0, 2, 3,
    0, 3, 2,
    1, 1, 2,
    1, 1, 3,
];

#[rustfmt::skip]
const BLOCK_POSITION_INVERT: [usize; 32] =
[
    0, 1, 2, 4, 3, 5, 6, 7, 12, 18, 13, 19, 8, 10, 14, 20, 16, 22, 9, 11, 15, 21, 17, 23,
    0, 1, 2, 4, 3, 5, 6, 7, // duplicates of 0-7 to eliminate modulus
];

fn crypt_pkm(out: &mut [u8], mut seed: u32) {
    out.chunks_mut(2).skip(4).for_each(|bytes| {
        seed = 0x41c64e6du32.wrapping_mul(seed).wrapping_add(0x6073);
        bytes[0] ^= (seed >> 16) as u8;
        bytes[1] ^= (seed >> 24) as u8;
    });
}

fn shuffle_array(data: &mut [u8], sv: usize, block_size: usize) {
    for block in 0..3 {
        let src_block = block;
        let dst_block = BLOCK_SWAP_DST[(sv * 3) + block];

        if src_block == dst_block {
            continue;
        }

        for i in 0..block_size {
            data.swap(
                8 + (src_block * block_size) + i,
                8 + (dst_block * block_size) + i,
            )
        }
    }
}

fn decrypt(ekx: &mut [u8], block_size: usize) {
    let seed = ekx.read(0);
    let sv = ((seed as usize) >> 13) & 31;
    crypt_pkm(ekx, seed);
    shuffle_array(ekx, sv, block_size);
}

fn encrypt(pkx: &mut [u8], block_size: usize) {
    let seed = pkx.read(0);
    let sv = ((seed as usize) >> 13) & 31;
    shuffle_array(pkx, BLOCK_POSITION_INVERT[sv], block_size);
    crypt_pkm(pkx, seed);
}

fn calculate_checksum(pkx: &[u8]) -> u16 {
    let mut checksum = 0u16;

    for chunks in pkx.chunks_exact(2) {
        let chunk = u16::from_le_bytes(chunks.try_into().unwrap());
        checksum = checksum.wrapping_add(chunk);
    }

    checksum
}

pub trait PokeCrypto: Reader {
    const PARTY_SIZE: usize;
    const STORED_SIZE: usize;
    const BLOCK_SIZE: usize;

    fn is_encrypted(data: &[u8]) -> bool;

    fn checksum(&self) -> u16;

    fn encrypt_raw(data: &mut [u8]) {
        if !Self::is_encrypted(data) {
            encrypt(data, Self::BLOCK_SIZE)
        }
    }

    fn decrypt_raw(data: &mut [u8]) {
        if Self::is_encrypted(data) {
            decrypt(data, Self::BLOCK_SIZE)
        }
    }

    fn calculate_checksum(&self) -> u16 {
        let data = self.as_slice();
        calculate_checksum(&data[8..Self::STORED_SIZE])
    }
}
