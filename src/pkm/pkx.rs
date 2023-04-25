use super::{poke_crypto, types};
use alloc::vec::Vec;
use no_std_io::Reader;

pub trait Pkx: Sized + Default + Reader {
    const STORED_SIZE: usize;
    const PARTY_SIZE: usize;
    const BLOCK_SIZE: usize;

    fn new<T: Into<Vec<u8>> + AsRef<[u8]>>(data: T) -> Self {
        if Self::is_encrypted(data.as_ref()) {
            Self::new_ekx(data)
        } else {
            Self::new_pkx(data)
        }
    }

    fn new_size_check<T: Into<Vec<u8>> + AsRef<[u8]>>(data: T) -> Result<Self, &'static str> {
        let pkx = Self::new(data);

        if !pkx.is_valid_size() {
            return Err("Invalid pkx size");
        }

        Ok(pkx)
    }

    fn new_ekx<T: Into<Vec<u8>> + AsRef<[u8]>>(data: T) -> Self {
        Self::new_pkx(Self::decrypt(data))
    }

    /// Defaults to an empty Pokemon if invalid
    fn new_or_default<T: Into<Vec<u8>> + AsRef<[u8]>>(data: T) -> Self {
        let pkm = Self::new(data.into());

        if pkm.is_valid() && pkm.is_valid_size() {
            pkm
        } else {
            Self::default()
        }
    }

    fn decrypt_if_needed<T: Into<Vec<u8>> + AsRef<[u8]>>(data: T) -> Vec<u8> {
        if Self::is_encrypted(data.as_ref()) {
            Self::decrypt(data)
        } else {
            data.into()
        }
    }

    fn encrypt_if_needed<T: Into<Vec<u8>> + AsRef<[u8]>>(data: T) -> Vec<u8> {
        if Self::is_encrypted(data.as_ref()) {
            data.into()
        } else {
            Self::encrypt(data)
        }
    }

    fn decrypt<T: Into<Vec<u8>> + AsRef<[u8]>>(data: T) -> Vec<u8> {
        poke_crypto::decrypt(data.into(), Self::BLOCK_SIZE)
    }

    fn encrypt<T: Into<Vec<u8>> + AsRef<[u8]>>(data: T) -> Vec<u8> {
        poke_crypto::encrypt(data.into(), Self::BLOCK_SIZE)
    }

    fn copy_encrypted(&self) -> Vec<u8> {
        Self::encrypt(self.get_slice()).to_vec()
    }

    fn copy_decrypted(&self) -> Vec<u8> {
        self.get_slice().to_vec()
    }

    fn is_valid_size(&self) -> bool {
        let len = self.get_slice().len();
        len == Self::STORED_SIZE || len == Self::PARTY_SIZE
    }

    fn new_pkx<T: Into<Vec<u8>> + AsRef<[u8]>>(data: T) -> Self;

    fn is_encrypted(data: &[u8]) -> bool;

    fn encryption_constant(&self) -> u32;

    fn sanity(&self) -> u16;

    fn checksum(&self) -> u16;

    fn species(&self) -> types::Species;

    fn pid(&self) -> u32;

    fn tid(&self) -> u16;

    fn sid(&self) -> u16;

    fn nature(&self) -> types::Nature;

    fn ability(&self) -> types::Ability;

    fn ability_number(&self) -> types::AbilityNumber;

    fn language(&self) -> types::Language;

    fn gender(&self) -> types::Gender;

    fn iv32(&self) -> u32;

    fn move1(&self) -> types::Move;

    fn move2(&self) -> types::Move;

    fn move3(&self) -> types::Move;

    fn move4(&self) -> types::Move;

    fn evs(&self) -> types::Stats;

    fn ot_friendship(&self) -> u8;

    fn ht_friendship(&self) -> u8;

    fn current_handler(&self) -> u8;

    fn calculate_checksum(&self) -> u16;

    fn tsv(&self) -> u16 {
        (self.tid() ^ self.sid()) >> 4
    }

    fn psv(&self) -> u16 {
        let pid = self.pid();
        let psv = ((pid >> 16) ^ (pid & 0xffff)) >> 4;
        psv as u16
    }

    fn is_shiny(&self) -> bool {
        self.is_valid() && self.psv() == self.tsv()
    }

    fn shiny_type(&self) -> Option<types::Shiny> {
        if !self.is_valid() {
            return None;
        }

        let pid = self.pid();
        let shiny_value = self.tid() ^ self.sid() ^ (pid as u16) ^ (pid >> 16) as u16;

        match shiny_value {
            0 => Some(types::Shiny::Square),
            num if num < 16 => Some(types::Shiny::Star),
            _ => None,
        }
    }

    fn ivs(&self) -> types::Stats {
        let iv32 = self.iv32();
        types::Stats {
            hp: (iv32 & 0x1F) as u8,
            atk: ((iv32 >> 5) & 0x1F) as u8,
            def: ((iv32 >> 10) & 0x1F) as u8,
            spe: ((iv32 >> 15) & 0x1F) as u8,
            spa: ((iv32 >> 20) & 0x1F) as u8,
            spd: ((iv32 >> 25) & 0x1F) as u8,
        }
    }

    fn hidden_power_num(&self) -> u8 {
        let ivs = self.ivs();
        ((((ivs.hp & 1)
            + ((ivs.atk & 1) << 1)
            + ((ivs.def & 1) << 2)
            + ((ivs.spe & 1) << 4)
            + ((ivs.spa & 1) << 5)
            + ((ivs.spd & 1) << 3)) as u16
            * 15)
            / 63) as u8
    }

    fn hidden_power(&self) -> types::HiddenPower {
        self.hidden_power_num().into()
    }

    fn gender_ratio(&self) -> types::GenderRatio {
        self.species().get_gender_ratio()
    }

    fn minted_nature(&self) -> types::Nature {
        self.nature()
    }

    fn is_egg(&self) -> bool {
        (self.iv32() >> 30) & 1 == 1
    }

    fn current_friendship(&self) -> u8 {
        if self.current_handler() == 0 {
            self.ot_friendship()
        } else {
            self.ht_friendship()
        }
    }

    fn is_valid(&self) -> bool {
        self.sanity() == 0
            && self.checksum() == self.calculate_checksum()
            && self.species() != types::Species::None
    }
}
