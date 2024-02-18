use binrw::{io::Cursor, BinRead, BinReaderExt};

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
}

impl<T> Reader for T
where
    T: AsRef<[u8]>,
{
    fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}
