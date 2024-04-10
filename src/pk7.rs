use crate::impl_read_prop;
use crate::pkx::Pkx;
use crate::poke_crypto::PokeCrypto;
use crate::reader::Reader;
use crate::strings::string_converter7;
use alloc::string::String;

pub struct Pk7 {
    data: [u8; Self::STORED_SIZE],
}

impl Default for Pk7 {
    fn default() -> Self {
        Self {
            data: [0; Self::STORED_SIZE],
        }
    }
}

impl Reader for Pk7 {
    fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl PokeCrypto for Pk7 {
    const PARTY_SIZE: usize = 0x104;
    const STORED_SIZE: usize = 0xE8;
    const BLOCK_SIZE: usize = 0x38;

    fn is_encrypted(data: &[u8]) -> bool {
        data.read::<u16>(0xc8) != 0 || data.read::<u16>(0x58) != 0
    }

    fn checksum(&self) -> u16 {
        self.read(0x06)
    }
}

impl Pk7 {
    pub fn new(mut data: [u8; Self::STORED_SIZE]) -> Self {
        Self::decrypt_raw(&mut data);
        Self { data }
    }
}

impl Pkx for Pk7 {
    impl_read_prop!(encryption_constant: u32 = 0x00);
    impl_read_prop!(sanity: u16 = 0x04);
    impl_read_prop!(species: u16 = 0x08);
    impl_read_prop!(held_item: u16 = 0x0a);
    impl_read_prop!(tid16: u16 = 0x0c);
    impl_read_prop!(sid16: u16 = 0x0e);
    impl_read_prop!(exp: u32 = 0x10);
    impl_read_prop!(ability_number: u8 = 0x15);
    impl_read_prop!(pid: u32 = 0x18);
    impl_read_prop!(nature: u8 = 0x1c);
    impl_read_prop!(ev_hp: u8 = 0x1e);
    impl_read_prop!(ev_atk: u8 = 0x1f);
    impl_read_prop!(ev_def: u8 = 0x20);
    impl_read_prop!(ev_spe: u8 = 0x21);
    impl_read_prop!(ev_spa: u8 = 0x22);
    impl_read_prop!(ev_spd: u8 = 0x23);
    impl_read_prop!(move1: u16 = 0x5a);
    impl_read_prop!(move2: u16 = 0x5c);
    impl_read_prop!(move3: u16 = 0x5e);
    impl_read_prop!(move4: u16 = 0x60);
    impl_read_prop!(move1_pp: u8 = 0x62);
    impl_read_prop!(move2_pp: u8 = 0x63);
    impl_read_prop!(move3_pp: u8 = 0x64);
    impl_read_prop!(move4_pp: u8 = 0x65);
    impl_read_prop!(move1_pp_ups: u8 = 0x66);
    impl_read_prop!(move2_pp_ups: u8 = 0x67);
    impl_read_prop!(move3_pp_ups: u8 = 0x68);
    impl_read_prop!(move4_pp_ups: u8 = 0x69);
    impl_read_prop!(iv32: u32 = 0x74);
    impl_read_prop!(current_handler: u8 = 0x93);
    impl_read_prop!(ht_friendship: u8 = 0xa2);
    impl_read_prop!(ot_friendship: u8 = 0xca);
    impl_read_prop!(ball: u8 = 0xdc);
    impl_read_prop!(language: u8 = 0xe3);
    impl_read_prop!(status_condition: u32 = 0xe8);
    // impl_read_prop!(stat_level: u8 = 0xec);
    // impl_read_prop!(stat_hp_current: u16 = 0xf0);
    // impl_read_prop!(stat_hp_max: u16 = 0xf2);
    // impl_read_prop!(stat_atk: u16 = 0xf4);
    // impl_read_prop!(stat_def: u16 = 0xf6);
    // impl_read_prop!(stat_spe: u16 = 0xf8);
    // impl_read_prop!(stat_spa: u16 = 0xfa);
    // impl_read_prop!(stat_spd: u16 = 0xfc);

    fn nickname(&self) -> String {
        string_converter7::get_string(&self.data[0x40..][..26])
    }

    fn ht_name(&self) -> String {
        string_converter7::get_string(&self.data[0x78..][..26])
    }

    fn ot_name(&self) -> String {
        string_converter7::get_string(&self.data[0xb0..][..26])
    }

    fn current_friendship(&self) -> u8 {
        if self.current_handler() == 0 {
            return self.ot_friendship();
        }
        self.ht_friendship()
    }

    fn form(&self) -> u8 {
        self.read::<u8>(0x1D) >> 3
    }

    fn is_egg(&self) -> bool {
        (self.iv32() >> 30) & 1 == 1
    }

    fn is_nicknamed(&self) -> bool {
        (self.iv32() >> 31) & 1 == 1
    }

    fn ot_gender(&self) -> u8 {
        self.read::<u8>(0xdd) >> 7
    }

    fn met_level(&self) -> u8 {
        self.read::<u8>(0xdd) & !0x80
    }

    fn ability(&self) -> u16 {
        self.read::<u8>(0x14).into()
    }

    fn gender(&self) -> u8 {
        let byte = self.read::<u8>(0x1D);
        (byte >> 1) & 3
    }

    fn valid_checksum(&self) -> bool {
        self.checksum() == self.calculate_checksum()
    }
}

#[cfg(test)]
mod test {
    use super::Pk7 as Pkm;
    use super::*;
    use crate::impl_test;
    use crate::types;

    const TEST_EKX: [u8; Pkm::STORED_SIZE] = [
        0xc8, 0x12, 0xb3, 0x6a, 0x00, 0x00, 0x8a, 0x9a, 0xf4, 0x4c, 0xcd, 0xd8, 0x39, 0xf8, 0x1b,
        0x37, 0xfe, 0xbf, 0x3b, 0x82, 0xd9, 0xce, 0xf5, 0x14, 0xce, 0xfb, 0x6d, 0x41, 0x6b, 0x2e,
        0x6a, 0xc8, 0xcb, 0xf9, 0xb6, 0x45, 0xbe, 0x2c, 0x48, 0x8d, 0x0c, 0x52, 0x34, 0x40, 0xa1,
        0xee, 0x03, 0x33, 0xa4, 0x83, 0x53, 0xad, 0x68, 0xf3, 0xce, 0x97, 0xf5, 0x0c, 0x53, 0x23,
        0xbb, 0x12, 0x85, 0x72, 0xed, 0xd2, 0x42, 0x97, 0xbe, 0xa8, 0xb9, 0xd6, 0x67, 0x5b, 0x5e,
        0x37, 0xcf, 0x73, 0x7a, 0xd7, 0x93, 0x6a, 0x3c, 0x2e, 0xa9, 0xd4, 0x30, 0xeb, 0xbf, 0xd5,
        0xa7, 0x92, 0x9d, 0x66, 0x4c, 0xf7, 0x29, 0x9c, 0x21, 0x19, 0xf1, 0x23, 0x03, 0x25, 0xd4,
        0xa0, 0x8f, 0xcb, 0x04, 0x85, 0xcc, 0xe4, 0xc9, 0x93, 0xae, 0x4c, 0x30, 0x71, 0x66, 0xe0,
        0xe2, 0xe0, 0xff, 0x68, 0x06, 0x48, 0xae, 0xf8, 0xe4, 0xb7, 0xc6, 0xfb, 0x90, 0x19, 0xec,
        0xc7, 0xd3, 0x81, 0x98, 0x68, 0x64, 0x70, 0x0a, 0x2a, 0x82, 0x57, 0xa3, 0x30, 0x51, 0x6a,
        0x50, 0x51, 0x69, 0x4d, 0xf1, 0xd3, 0x6f, 0x44, 0xdc, 0xf6, 0xba, 0xa8, 0xee, 0x82, 0x4f,
        0x28, 0xc6, 0x91, 0xb5, 0x51, 0x27, 0x64, 0x74, 0x98, 0x85, 0xdc, 0x6b, 0x17, 0x18, 0x72,
        0x4a, 0x30, 0xf4, 0x4c, 0xf9, 0x97, 0x97, 0x36, 0xb4, 0xa9, 0x49, 0x60, 0xc6, 0xe2, 0x06,
        0xe3, 0x13, 0x62, 0x15, 0xe7, 0x68, 0x29, 0xec, 0x91, 0xe5, 0xc8, 0xcf, 0xa7, 0xb2, 0x1f,
        0x31, 0xbd, 0xf0, 0x7d, 0x49, 0x09, 0x7a, 0x83, 0xb4, 0xb7, 0xba, 0xd5, 0xa3, 0x80, 0x56,
        0xaf, 0xa6, 0x28, 0x01, 0x9c, 0x99, 0xce,
    ];

    const TEST_PKX: [u8; Pkm::STORED_SIZE] = [
        0xC8, 0x12, 0xB3, 0x6A, 0x00, 0x00, 0x8A, 0x9A, 0x5C, 0x00, 0x00, 0x00, 0xB9, 0x88, 0x8D,
        0x49, 0x00, 0x00, 0x00, 0x00, 0x1A, 0x01, 0x00, 0x00, 0x7A, 0x0F, 0xAA, 0xCE, 0x05, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x47, 0x00, 0x61, 0x00, 0x73, 0x00, 0x74, 0x00, 0x6C, 0x00, 0x79,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x5F, 0x00, 0x7A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x5F, 0x00, 0x7A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7A, 0x2A, 0x9D, 0x23,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x4B, 0x00,
        0x48, 0x00, 0x65, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12,
        0x08, 0x17, 0x12, 0x08, 0x17, 0x00, 0x62, 0xEA, 0x4E, 0x00, 0x17, 0x01, 0x00, 0x21, 0x31,
        0x34, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
    ];

    mod is_encrypted {
        use super::*;

        #[test]
        fn encrypted() {
            assert_eq!(Pkm::is_encrypted(&TEST_EKX), true)
        }

        #[test]
        fn decrypted() {
            assert_eq!(Pkm::is_encrypted(&TEST_PKX), false)
        }
    }

    #[test]
    fn should_decrypt() {
        let mut ekx = TEST_EKX.clone();
        Pkm::decrypt_raw(&mut ekx);
        assert_eq!(ekx, TEST_PKX);
    }

    #[test]
    fn should_encrypt() {
        let mut pkx = TEST_PKX.clone();
        Pkm::encrypt_raw(&mut pkx);
        assert_eq!(pkx, TEST_EKX);
    }

    impl_test!(held_item, 0);
    impl_test!(form, 0);
    impl_test!(is_nicknamed, false);
    impl_test!(exp, 0);
    impl_test!(tid16, 35001);
    impl_test!(sid16, 18829);
    impl_test!(ot_gender_t, types::Gender::Male);
    impl_test!(ball, 23);
    impl_test!(met_level, 1);
    impl_test!(species_t, types::Species::Gastly);
    impl_test!(pid, 0xceaa0f7a);
    impl_test!(tsv, 3091);
    impl_test!(psv, 3101);
    impl_test!(nature_t, types::Nature::Bold);
    impl_test!(ability_t, types::Ability::Levitate);
    impl_test!(ability_number_t, types::AbilityNumber::First);
    impl_test!(hidden_power_t, types::HiddenPower::Electric);
    impl_test!(language_t, types::Language::English);
    impl_test!(gender_t, types::Gender::Female);
    impl_test!(move1_t, types::Move::Hypnosis);
    impl_test!(move2_t, types::Move::Lick);
    impl_test!(move3_t, types::Move::None);
    impl_test!(move4_t, types::Move::None);
    impl_test!(move1_pp, 20);
    impl_test!(move2_pp, 30);
    impl_test!(move3_pp, 0);
    impl_test!(move4_pp, 0);
    impl_test!(move1_pp_ups, 0);
    impl_test!(move2_pp_ups, 0);
    impl_test!(move3_pp_ups, 0);
    impl_test!(move4_pp_ups, 0);
    impl_test!(iv_hp, 26);
    impl_test!(iv_atk, 19);
    impl_test!(iv_def, 10);
    impl_test!(iv_spa, 25);
    impl_test!(iv_spd, 17);
    impl_test!(iv_spe, 26);
    impl_test!(ev_hp, 0);
    impl_test!(ev_atk, 0);
    impl_test!(ev_def, 0);
    impl_test!(ev_spa, 0);
    impl_test!(ev_spd, 0);
    impl_test!(ev_spe, 0);
    impl_test!(ot_friendship, 138);
    impl_test!(ht_friendship, 0);
    impl_test!(is_egg, false);
    impl_test!(current_handler, 0);
    impl_test!(current_friendship, 138);
    impl_test!(sanity, 0);
    impl_test!(checksum, 0x9a8a);
    impl_test!(calculate_checksum, 0x9a8a);
    impl_test!(is_valid, true);
    impl_test!(is_shiny, false);
    impl_test!(shiny_type, None);

    impl_test!(nickname, "Gastly");
    impl_test!(ot_name, "PKHeX");
    impl_test!(ht_name, "");

    impl_test!(status_condition, 0);
    // impl_test!(stat_level, 0);
    // impl_test!(stat_hp_max, 0);
    // impl_test!(stat_atk, 0);
    // impl_test!(stat_def, 0);
    // impl_test!(stat_spe, 0);
    // impl_test!(stat_spa, 0);
    // impl_test!(stat_spd, 0);
    // impl_test!(stat_hp_current, 0);

    #[test]
    fn should_return_not_shiny_for_default() {
        let pkx = Pkm::default();
        assert_eq!(pkx.is_shiny(), false)
    }
}
