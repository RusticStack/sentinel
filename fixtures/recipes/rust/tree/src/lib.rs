pub fn helper() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    #[test]
    fn helper_is_one() {
        assert_eq!(super::helper(), 1);
    }
}
