#[macro_export]
macro_rules! impl_test {
    ($test_name:ident, $expected:expr) => {
        #[test]
        fn $test_name() {
            let pkx = Pkm::new(TEST_EKX);
            assert_eq!(pkx.$test_name(), $expected);
        }
    };
}
