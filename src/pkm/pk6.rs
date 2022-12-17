use super::{pkx::Pkx, poke_crypto, types};
use alloc::{vec, vec::Vec};
use no_std_io::{EndianRead, Reader};

pub struct Pk6 {
    data: Vec<u8>,
}

impl Default for Pk6 {
    fn default() -> Self {
        Self {
            data: vec![0; Pk6::STORED_SIZE],
        }
    }
}

impl Reader for Pk6 {
    fn get_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Pkx for Pk6 {
    const STORED_SIZE: usize = 0xE8;
    const PARTY_SIZE: usize = 0x104;
    const BLOCK_SIZE: usize = 0x38;

    fn new_pkx<T: Into<Vec<u8>> + AsRef<[u8]>>(data: T) -> Self {
        Self { data: data.into() }
    }

    fn is_encrypted(data: &[u8]) -> bool {
        data.default_read_le::<u16>(0xc8) != 0 || data.default_read_le::<u16>(0x58) != 0
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
        poke_crypto::calculate_checksum(&self.data[8..Pk6::STORED_SIZE])
    }
}

pub type Pk6PartyBytes = [u8; Pk6::PARTY_SIZE];

impl From<Pk6PartyBytes> for Pk6 {
    fn from(data: Pk6PartyBytes) -> Self {
        Self::new_or_default(data)
    }
}

pub type Pk6StoredBytes = [u8; Pk6::STORED_SIZE];

impl From<Pk6StoredBytes> for Pk6 {
    fn from(data: Pk6StoredBytes) -> Self {
        Self::new_or_default(data)
    }
}

#[derive(EndianRead)]
pub struct Ek6 {
    data: Pk6StoredBytes,
}

impl Default for Ek6 {
    fn default() -> Self {
        Self {
            data: [0; Pk6::STORED_SIZE],
        }
    }
}

impl From<Ek6> for Pk6 {
    fn from(ekx: Ek6) -> Self {
        ekx.data.into()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const TEST_EKX: Pk6StoredBytes = [
        0x80, 0x5c, 0x86, 0x02, 0x00, 0x00, 0xd6, 0x41, 0x20, 0x0e, 0x56, 0x4f, 0xaa, 0xf1, 0xf4,
        0x2f, 0xa5, 0x9e, 0xcc, 0xfe, 0x8b, 0xf2, 0x32, 0x20, 0x51, 0xd1, 0x99, 0xdd, 0x42, 0xd2,
        0x55, 0xe5, 0x05, 0x1f, 0x85, 0x2a, 0x62, 0xe2, 0x2a, 0x14, 0x5a, 0x21, 0x96, 0xdb, 0x76,
        0x2e, 0xd6, 0x4e, 0x72, 0xa0, 0x72, 0x08, 0xa0, 0x2b, 0x59, 0x35, 0xf9, 0x56, 0xba, 0xc6,
        0x92, 0x55, 0x0c, 0x01, 0xf9, 0x2b, 0xdb, 0x58, 0xbd, 0x84, 0x5a, 0xc9, 0x94, 0x77, 0x96,
        0x72, 0x1d, 0x5b, 0x13, 0xd1, 0x8a, 0x7b, 0x7e, 0x07, 0x93, 0xec, 0xe2, 0x81, 0x08, 0x4b,
        0x13, 0xfa, 0xda, 0x5f, 0x4a, 0x6c, 0x0a, 0xcb, 0x50, 0x90, 0xb9, 0x48, 0x37, 0x99, 0x68,
        0x9b, 0x51, 0xe9, 0xe7, 0x1b, 0xfe, 0x80, 0xcb, 0x56, 0xad, 0x23, 0xb8, 0x56, 0x50, 0x60,
        0x47, 0xf4, 0x59, 0x27, 0xee, 0x49, 0xb3, 0x76, 0xcb, 0xa7, 0xef, 0x77, 0xe7, 0x59, 0xdb,
        0xd8, 0xe9, 0x1e, 0x4e, 0xe9, 0xf5, 0xa9, 0xf3, 0xb7, 0x77, 0x93, 0x7c, 0x45, 0x86, 0x5e,
        0xef, 0x41, 0x3f, 0x0d, 0xb1, 0xb6, 0x66, 0xf2, 0xd8, 0x86, 0x98, 0x64, 0xf2, 0xf2, 0x7f,
        0x4b, 0x86, 0xf6, 0x46, 0xda, 0x44, 0x7f, 0xec, 0x75, 0x34, 0xd4, 0xcd, 0x58, 0x4b, 0x7a,
        0x33, 0x21, 0x3e, 0xdf, 0x68, 0xb1, 0xe9, 0xbd, 0x55, 0x11, 0x91, 0x28, 0x53, 0x6e, 0xfb,
        0x5a, 0xc1, 0xcf, 0x38, 0x72, 0xec, 0x04, 0xd1, 0xac, 0xe1, 0x8c, 0x5a, 0x51, 0x30, 0xb4,
        0x8b, 0xa4, 0xec, 0x45, 0xbc, 0x43, 0x6d, 0x14, 0xb8, 0x8e, 0x93, 0x80, 0x91, 0x1e, 0x91,
        0xca, 0x14, 0xb7, 0xdf, 0xf2, 0xb3, 0x26,
    ];

    const TEST_PKX: Pk6StoredBytes = [
        0x80, 0x5c, 0x86, 0x02, 0x00, 0x00, 0xd6, 0x41, 0x84, 0x00, 0x18, 0x01, 0x56, 0xf6, 0x42,
        0xc8, 0x40, 0x42, 0x0f, 0x00, 0x96, 0x04, 0x00, 0x00, 0x23, 0x0f, 0x37, 0x31, 0x03, 0x04,
        0xfc, 0x00, 0x06, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x31, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x64, 0x00, 0x61, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x6e,
        0x00, 0x74, 0x00, 0x20, 0x00, 0x36, 0x00, 0x49, 0x00, 0x56, 0x00, 0x73, 0x00, 0x00, 0x00,
        0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xbf,
        0x45, 0x00, 0x56, 0x00, 0x92, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2c, 0x31,
        0x0a, 0x12, 0x2c, 0x31, 0x10, 0x31, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x46, 0x00, 0x03,
        0x04, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x69, 0x00,
        0x74, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x20, 0x00, 0x69, 0x00, 0x73, 0x00, 0x20, 0x00, 0x92,
        0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x03, 0x07, 0x0f, 0x97, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x0c, 0x0c, 0x19, 0x00, 0x00, 0x00, 0x94, 0x00, 0x0b, 0x1e, 0x00, 0x18, 0x12,
        0x0a, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,
    ];

    mod is_encrypted {
        use super::*;

        #[test]
        fn encrypted() {
            assert_eq!(Pk6::is_encrypted(&TEST_EKX), true)
        }

        #[test]
        fn decrypted() {
            assert_eq!(Pk6::is_encrypted(&TEST_PKX), false)
        }
    }

    #[test]
    fn should_decrypt() {
        let pkx = Pk6::decrypt(TEST_EKX);
        assert_eq!(pkx, TEST_PKX);
    }

    #[test]
    fn should_encrypt() {
        let ekx = Pk6::encrypt(TEST_PKX);
        assert_eq!(ekx, TEST_EKX);
    }

    #[test]
    fn should_get_encrypted() {
        let ekx = Pk6::new(TEST_PKX).copy_encrypted();
        assert_eq!(ekx, TEST_EKX);
    }

    #[test]
    fn stored_size() {
        assert_eq!(core::mem::size_of::<Pk6StoredBytes>(), Pk6::STORED_SIZE);
    }

    #[test]
    fn party_size() {
        assert_eq!(core::mem::size_of::<Pk6PartyBytes>(), Pk6::PARTY_SIZE);
    }

    #[test]
    fn should_read_species() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.species(), types::Species::Ditto);
    }

    #[test]
    fn should_read_pid() {
        let pkx = Pk6::new(TEST_EKX);
        let pid = 0x31370F23;
        assert_eq!(pkx.pid(), pid)
    }

    #[test]
    fn should_read_tid() {
        let pkx = Pk6::new(TEST_EKX);
        let tid = 63062;
        assert_eq!(pkx.tid(), tid)
    }

    #[test]
    fn should_read_sid() {
        let pkx = Pk6::new(TEST_EKX);
        let sid = 51266;
        assert_eq!(pkx.sid(), sid)
    }

    #[test]
    fn should_read_tsv() {
        let pkx = Pk6::new(TEST_EKX);
        let tsv = 0993;
        assert_eq!(pkx.tsv(), tsv)
    }

    #[test]
    fn should_read_psv() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.psv(), 0993)
    }

    #[test]
    fn should_read_nature() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.nature(), types::Nature::Adamant)
    }

    #[test]
    fn should_read_minted_nature() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.minted_nature(), types::Nature::Adamant)
    }

    #[test]
    fn should_read_ability() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.ability(), types::Ability::Imposter)
    }

    #[test]
    fn should_read_ability_number() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.ability_number(), types::AbilityNumber::Hidden)
    }

    #[test]
    fn should_read_hidden_power() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.hidden_power(), types::HiddenPower::Dark)
    }

    #[test]
    fn should_read_language() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.language(), types::Language::French)
    }

    #[test]
    fn should_read_gender() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.gender(), types::Gender::Genderless)
    }

    #[test]
    fn should_read_move1() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.move1(), types::Move::Transform)
    }

    #[test]
    fn should_read_move2() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.move2(), types::Move::None)
    }

    #[test]
    fn should_read_move3() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.move3(), types::Move::None)
    }

    #[test]
    fn should_read_move4() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.move4(), types::Move::None)
    }

    #[test]
    fn should_read_ivs() {
        let pkx = Pk6::new(TEST_EKX);
        let stats = types::Stats {
            hp: 31,
            atk: 31,
            def: 31,
            spa: 31,
            spd: 31,
            spe: 31,
        };
        assert_eq!(pkx.ivs(), stats)
    }

    #[test]
    fn should_read_evs() {
        let pkx = Pk6::new(TEST_EKX);
        let stats = types::Stats {
            hp: 252,
            atk: 0,
            def: 6,
            spa: 0,
            spd: 0,
            spe: 252,
        };
        assert_eq!(pkx.evs(), stats)
    }

    #[test]
    fn should_read_ot_friendship() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.ot_friendship(), 70)
    }

    #[test]
    fn should_read_ht_friendship() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.ht_friendship(), 70)
    }

    #[test]
    fn should_read_is_egg() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.is_egg(), false)
    }

    #[test]
    fn should_read_current_handler() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.current_handler(), 1)
    }

    #[test]
    fn should_read_current_friendship() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.current_friendship(), 70)
    }

    #[test]
    fn should_read_sanity() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.sanity(), 0)
    }

    #[test]
    fn should_read_checksum() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.checksum(), 0x41d6)
    }

    #[test]
    fn should_calculate_checksum() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.calculate_checksum(), 0x41d6)
    }

    #[test]
    fn should_read_is_valid() {
        let pkx = Pk6::new(TEST_EKX);
        assert_eq!(pkx.is_valid(), true)
    }

    #[test]
    fn should_return_not_shiny_for_default() {
        let pkx = Pk6::default();
        assert_eq!(pkx.is_shiny(), false)
    }
}
