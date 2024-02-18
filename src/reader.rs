use binrw::io::{Cursor, Read};
use binrw::{BinRead, BinReaderExt};

pub trait Reader {
    fn as_slice(&self) -> &[u8];

    fn read<'a, T>(&self, offset: u64) -> T
    where
        T: BinRead + Default,
        <T as BinRead>::Args<'a>: Default,
    {
        let mut cursor = Cursor::new(self.as_slice());
        cursor.set_position(offset);
        cursor.read_le().unwrap_or_default()
    }

    fn read_array<const LEN: usize>(&self, offset: u64) -> [u8; LEN] {
        let mut buf = [0u8; LEN];
        let mut cursor = Cursor::new(self.as_slice());
        cursor.set_position(offset);
        let _ = Read::read(&mut cursor, &mut buf);
        buf
    }
}

impl<T> Reader for T
where
    T: AsRef<[u8]>,
{
    fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}
