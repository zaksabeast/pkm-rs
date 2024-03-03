use super::string_converter::sanitize_char;
use alloc::string::String;

pub fn get_string(data: &[u8]) -> String {
    let utf16_iter = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));

    char::decode_utf16(utf16_iter)
        .take_while(|c| *c != Ok('\0'))
        .filter_map(|char| char.ok().map(sanitize_char))
        .collect()
}
