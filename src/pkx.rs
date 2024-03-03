use crate::types;
use alloc::string::String;

pub trait Pkx: Sized {
    // Surface Properties
    fn species(&self) -> u16;
    fn nickname(&self) -> String;
    fn held_item(&self) -> u16;
    fn gender(&self) -> u8;
    fn nature(&self) -> u8;
    fn stat_nature(&self) -> u8 {
        self.nature()
    }
    fn ability(&self) -> u16;
    fn current_friendship(&self) -> u8;
    fn form(&self) -> u8;
    fn is_egg(&self) -> bool;
    fn is_nicknamed(&self) -> bool;
    fn exp(&self) -> u32;
    fn tid16(&self) -> u16;
    fn sid16(&self) -> u16;
    fn ot_name(&self) -> String;
    fn ot_gender(&self) -> u8;
    fn ball(&self) -> u8;
    fn met_level(&self) -> u8;

    // Battle
    fn move1(&self) -> u16;
    fn move2(&self) -> u16;
    fn move3(&self) -> u16;
    fn move4(&self) -> u16;
    fn move1_pp(&self) -> u8;
    fn move2_pp(&self) -> u8;
    fn move3_pp(&self) -> u8;
    fn move4_pp(&self) -> u8;
    fn move1_pp_ups(&self) -> u8;
    fn move2_pp_ups(&self) -> u8;
    fn move3_pp_ups(&self) -> u8;
    fn move4_pp_ups(&self) -> u8;
    fn ev_hp(&self) -> u8;
    fn ev_atk(&self) -> u8;
    fn ev_def(&self) -> u8;
    fn ev_spe(&self) -> u8;
    fn ev_spa(&self) -> u8;
    fn ev_spd(&self) -> u8;
    fn iv_hp(&self) -> u8 {
        (self.iv32() & 0x1F) as u8
    }
    fn iv_atk(&self) -> u8 {
        ((self.iv32() >> 5) & 0x1F) as u8
    }
    fn iv_def(&self) -> u8 {
        ((self.iv32() >> 10) & 0x1F) as u8
    }
    fn iv_spe(&self) -> u8 {
        ((self.iv32() >> 15) & 0x1F) as u8
    }
    fn iv_spa(&self) -> u8 {
        ((self.iv32() >> 20) & 0x1F) as u8
    }
    fn iv_spd(&self) -> u8 {
        ((self.iv32() >> 25) & 0x1F) as u8
    }
    fn status_condition(&self) -> u32;

    // Cannot implement until stat loading and box -> party conversion is added
    // fn stat_level(&self) -> u8;
    // fn stat_hp_max(&self) -> u16;
    // fn stat_hp_current(&self) -> u16;
    // fn stat_atk(&self) -> u16;
    // fn stat_def(&self) -> u16;
    // fn stat_spe(&self) -> u16;
    // fn stat_spa(&self) -> u16;
    // fn stat_spd(&self) -> u16;

    fn encryption_constant(&self) -> u32;
    fn sanity(&self) -> u16;
    fn valid_checksum(&self) -> bool;
    fn pid(&self) -> u32;
    fn ability_number(&self) -> u8;
    fn language(&self) -> u8;
    fn iv32(&self) -> u32;
    fn ot_friendship(&self) -> u8;
    fn ht_friendship(&self) -> u8;
    fn current_handler(&self) -> u8;
    fn ht_name(&self) -> String;

    fn tsv(&self) -> u16 {
        (self.tid16() ^ self.sid16()) >> 4
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

        let shiny_value = self.tsv() ^ self.psv();

        match shiny_value {
            0 => Some(types::Shiny::Square),
            num if num < 16 => Some(types::Shiny::Star),
            _ => None,
        }
    }

    fn hidden_power(&self) -> u8 {
        ((((self.iv_hp() & 1)
            + ((self.iv_atk() & 1) << 1)
            + ((self.iv_def() & 1) << 2)
            + ((self.iv_spe() & 1) << 3)
            + ((self.iv_spa() & 1) << 4)
            + ((self.iv_spd() & 1) << 5)) as u16
            * 15)
            / 63) as u8
    }

    fn species_t(&self) -> types::Species {
        self.species().into()
    }
    fn move1_t(&self) -> types::Move {
        self.move1().into()
    }
    fn move2_t(&self) -> types::Move {
        self.move2().into()
    }
    fn move3_t(&self) -> types::Move {
        self.move3().into()
    }
    fn move4_t(&self) -> types::Move {
        self.move4().into()
    }
    fn ot_gender_t(&self) -> types::Gender {
        self.ot_gender().into()
    }
    fn gender_t(&self) -> types::Gender {
        self.gender().into()
    }
    fn nature_t(&self) -> types::Nature {
        self.nature().into()
    }
    fn stat_nature_t(&self) -> types::Nature {
        self.nature_t()
    }
    fn ability_t(&self) -> types::Ability {
        self.ability().into()
    }
    fn ability_number_t(&self) -> types::AbilityNumber {
        self.ability_number().into()
    }
    fn language_t(&self) -> types::Language {
        self.language().into()
    }
    fn hidden_power_t(&self) -> types::HiddenPower {
        self.hidden_power().into()
    }

    fn gender_ratio(&self) -> types::GenderRatio {
        self.species_t().get_gender_ratio()
    }

    fn is_valid(&self) -> bool {
        self.sanity() == 0 && self.valid_checksum() && self.species_t() != types::Species::None
    }
}
