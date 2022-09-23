use super::{pkx::Pkx, poke_crypto, types};
use core::convert::TryInto;
use no_std_io::Reader;

pub type Pk7Bytes = [u8; Pk7::STORED_SIZE];

pub struct Pk7 {
    data: Pk7Bytes,
}

impl Default for Pk7 {
    fn default() -> Self {
        Self {
            data: [0; Pk7::STORED_SIZE],
        }
    }
}

impl Reader for Pk7 {
    fn get_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Pkx for Pk7 {
    type StoredBytes = Pk7Bytes;
    const STORED_SIZE: usize = 232;
    const BLOCK_SIZE: usize = 56;

    fn new(data: Self::StoredBytes) -> Self {
        let seed_bytes: [u8; 4] = data[0..4].try_into().unwrap();
        let seed = u32::from_le_bytes(seed_bytes);
        Self {
            data: poke_crypto::decrypt::<{ Pk7::STORED_SIZE }, { Pk7::BLOCK_SIZE }>(data, seed),
        }
    }

    fn encryption_constant(&self) -> u32 {
        self.default_read_le(0x00)
    }

    fn sanity(&self) -> u16 {
        self.default_read_le(0x04)
    }

    fn checksum(&self) -> u16 {
        self.default_read_le(0x06)
    }

    fn species(&self) -> types::Species {
        self.default_read_le::<u16>(0x08).into()
    }

    fn tid(&self) -> u16 {
        self.default_read_le(0x0C)
    }

    fn sid(&self) -> u16 {
        self.default_read_le(0x0E)
    }

    fn ability(&self) -> types::Ability {
        let ability: u8 = self.default_read(0x14);
        (ability as u16).into()
    }

    fn ability_number(&self) -> types::AbilityNumber {
        self.default_read::<u8>(0x15).into()
    }

    fn pid(&self) -> u32 {
        self.default_read_le(0x18)
    }

    fn nature(&self) -> types::Nature {
        self.default_read::<u8>(0x1C).into()
    }

    fn gender(&self) -> types::Gender {
        let byte = self.default_read::<u8>(0x1D);
        ((byte >> 1) & 3).into()
    }

    fn evs(&self) -> types::Stats {
        types::Stats {
            hp: self.default_read(0x1E),
            atk: self.default_read(0x1F),
            def: self.default_read(0x20),
            spe: self.default_read(0x21),
            spa: self.default_read(0x22),
            spd: self.default_read(0x23),
        }
    }

    fn move1(&self) -> types::Move {
        self.default_read::<u16>(0x5A).into()
    }

    fn move2(&self) -> types::Move {
        self.default_read::<u16>(0x5C).into()
    }

    fn move3(&self) -> types::Move {
        self.default_read::<u16>(0x5E).into()
    }

    fn move4(&self) -> types::Move {
        self.default_read::<u16>(0x60).into()
    }

    fn iv32(&self) -> u32 {
        self.default_read_le(0x74)
    }

    fn current_handler(&self) -> u8 {
        self.default_read(0x93)
    }

    fn ht_friendship(&self) -> u8 {
        self.default_read(0xA2)
    }

    fn ot_friendship(&self) -> u8 {
        self.default_read(0xCA)
    }

    fn language(&self) -> types::Language {
        self.default_read::<u8>(0xE3).into()
    }

    fn calculate_checksum(&self) -> u16 {
        poke_crypto::calculate_checksum(&self.data[8..Pk7::STORED_SIZE])
    }
}

impl From<Pk7Bytes> for Pk7 {
    fn from(data: Pk7Bytes) -> Self {
        Self::new_or_default(data)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const TEST_EKX: Pk7Bytes = [
        0xde, 0xda, 0x09, 0x87, 0x00, 0x00, 0x4e, 0x4b, 0x96, 0x25, 0xae, 0xf6, 0x89, 0xe7, 0x20,
        0x92, 0xc7, 0xf0, 0x8b, 0xa5, 0xe2, 0x3e, 0x6e, 0xd9, 0x52, 0x2a, 0x18, 0x04, 0x3e, 0x76,
        0xec, 0x86, 0x0f, 0x3c, 0x79, 0x44, 0xca, 0x7c, 0xe4, 0xa4, 0x85, 0x05, 0x3d, 0x60, 0x71,
        0x09, 0xb4, 0x72, 0x56, 0xab, 0xc3, 0xc4, 0x6e, 0x79, 0xd1, 0x41, 0xfc, 0xe9, 0xd9, 0x61,
        0x22, 0x04, 0x0e, 0x1f, 0xe5, 0xdf, 0xca, 0xfe, 0x57, 0x58, 0x6e, 0xcc, 0xd7, 0x81, 0xa1,
        0xf8, 0xcb, 0xf5, 0x57, 0xcd, 0xb8, 0x30, 0xbf, 0xd1, 0xe2, 0xd9, 0xb8, 0x8f, 0x79, 0x20,
        0x8c, 0x2e, 0x28, 0x50, 0x01, 0xeb, 0xe1, 0x86, 0xb5, 0x34, 0x8a, 0xfb, 0x10, 0x85, 0x1f,
        0xc6, 0xce, 0x36, 0x0f, 0x6f, 0xf2, 0xd6, 0x23, 0x06, 0x12, 0xaa, 0x75, 0xce, 0xce, 0xe0,
        0x95, 0xf3, 0xd5, 0x0f, 0x96, 0xe0, 0x44, 0x22, 0x57, 0x89, 0xfe, 0xaf, 0xda, 0x27, 0x53,
        0xa0, 0x61, 0xd2, 0x6a, 0x5a, 0xd2, 0x4d, 0xaf, 0x50, 0x0a, 0xec, 0x8c, 0x31, 0xb7, 0x48,
        0x35, 0x56, 0x3d, 0xeb, 0x93, 0xd5, 0xda, 0xed, 0xc1, 0x17, 0x5d, 0x1a, 0xce, 0xf2, 0xa8,
        0xa9, 0xc1, 0xc6, 0x41, 0xf7, 0x91, 0x38, 0x80, 0x4f, 0xf7, 0x17, 0x61, 0x1a, 0x68, 0x62,
        0xc0, 0x4c, 0x7d, 0xc4, 0x4f, 0x58, 0xe7, 0x89, 0x72, 0xae, 0x09, 0x17, 0x17, 0xa2, 0x36,
        0x01, 0xae, 0x36, 0x72, 0x09, 0x0a, 0xcc, 0xc6, 0xd4, 0xa1, 0xe6, 0x72, 0xb6, 0x65, 0xb7,
        0x79, 0x5c, 0x5b, 0x88, 0xbb, 0x23, 0xc8, 0x8d, 0x3a, 0x81, 0xd3, 0x2f, 0xf1, 0x86, 0x1d,
        0x0f, 0xa9, 0x96, 0xc6, 0x30, 0xbf, 0x71,
    ];

    #[test]
    fn should_decrypt() {
        let result: Pk7Bytes = [
            0xde, 0xda, 0x09, 0x87, 0x00, 0x00, 0x4e, 0x4b, 0xd8, 0x02, 0x00, 0x00, 0x55, 0x0d,
            0x14, 0x96, 0x30, 0x01, 0x00, 0x00, 0x43, 0x01, 0x00, 0x00, 0xb4, 0x93, 0x7a, 0xe9,
            0x0c, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x6f, 0x00, 0x70, 0x00,
            0x70, 0x00, 0x6c, 0x00, 0x69, 0x00, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x37, 0x00, 0x2d, 0x00, 0x00, 0x00,
            0x23, 0x19, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x8e, 0x2a, 0x55, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x56, 0x00, 0x92, 0xe0,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x12, 0x08, 0x16, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x85, 0x00, 0x21,
            0x31, 0x0b, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
        ];

        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.get_slice(), result);
    }

    #[test]
    fn pk7_data_size_should_be_232() {
        assert_eq!(core::mem::size_of::<Pk7Bytes>(), Pk7::STORED_SIZE);
    }

    #[test]
    fn should_read_species() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.species(), types::Species::Popplio);
    }

    #[test]
    fn should_read_pid() {
        let pkx = Pk7::new(TEST_EKX);
        let pid = 0xE97A93B4;
        assert_eq!(pkx.pid(), pid)
    }

    #[test]
    fn should_read_tid() {
        let pkx = Pk7::new(TEST_EKX);
        let tid = 03413;
        assert_eq!(pkx.tid(), tid)
    }

    #[test]
    fn should_read_sid() {
        let pkx = Pk7::new(TEST_EKX);
        let sid = 38420;
        assert_eq!(pkx.sid(), sid)
    }

    #[test]
    fn should_read_tsv() {
        let pkx = Pk7::new(TEST_EKX);
        let tsv = 2484;
        assert_eq!(pkx.tsv(), tsv)
    }

    #[test]
    fn should_read_psv() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.psv(), 1964)
    }

    #[test]
    fn should_read_nature() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.nature(), types::Nature::Serious)
    }

    #[test]
    fn should_read_minted_nature() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.minted_nature(), types::Nature::Serious)
    }

    #[test]
    fn should_read_ability() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.ability(), types::Ability::Torrent)
    }

    #[test]
    fn should_read_ability_number() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.ability_number(), types::AbilityNumber::First)
    }

    #[test]
    fn should_read_hidden_power() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.hidden_power(), types::HiddenPower::Ground)
    }

    #[test]
    fn should_read_language() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.language(), types::Language::English)
    }

    #[test]
    fn should_read_gender() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.gender(), types::Gender::Male)
    }

    #[test]
    fn should_read_move1() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.move1(), types::Move::Pound)
    }

    #[test]
    fn should_read_move2() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.move2(), types::Move::WaterGun)
    }

    #[test]
    fn should_read_move3() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.move3(), types::Move::Growl)
    }

    #[test]
    fn should_read_move4() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.move4(), types::Move::None)
    }

    #[test]
    fn should_read_ivs() {
        let pkx = Pk7::new(TEST_EKX);
        let stats = types::Stats {
            hp: 14,
            atk: 20,
            def: 10,
            spa: 21,
            spd: 30,
            spe: 10,
        };
        assert_eq!(pkx.ivs(), stats)
    }

    #[test]
    fn should_read_evs() {
        let pkx = Pk7::new(TEST_EKX);
        let stats = types::Stats {
            hp: 0,
            atk: 0,
            def: 0,
            spa: 0,
            spd: 0,
            spe: 4,
        };
        assert_eq!(pkx.evs(), stats)
    }

    #[test]
    fn should_read_ot_friendship() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.ot_friendship(), 87)
    }

    #[test]
    fn should_read_ht_friendship() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.ht_friendship(), 0)
    }

    #[test]
    fn should_read_is_egg() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.is_egg(), false)
    }

    #[test]
    fn should_read_current_handler() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.current_handler(), 0)
    }

    #[test]
    fn should_read_current_friendship() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.current_friendship(), 87)
    }

    #[test]
    fn should_read_sanity() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.sanity(), 0)
    }

    #[test]
    fn should_read_checksum() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.checksum(), 0x4b4e)
    }

    #[test]
    fn should_calculate_checksum() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.calculate_checksum(), 0x4b4e)
    }

    #[test]
    fn should_read_is_valid() {
        let pkx = Pk7::new(TEST_EKX);
        assert_eq!(pkx.is_valid(), true)
    }

    #[test]
    fn should_return_not_shiny_for_default() {
        let pkx = Pk7::default();
        assert_eq!(pkx.is_shiny(), false)
    }
}
