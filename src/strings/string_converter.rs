pub fn sanitize_char(chr: char) -> char {
    match chr {
        '\u{E08F}' => '♀',
        '\u{E08E}' => '♂',
        '\u{246E}' => '♀',
        '\u{246D}' => '♂',
        _ => chr,
    }
}
