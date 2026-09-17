pub fn helper() -> u32 {
    2
}

#[cfg(test)]
mod tests {
    #[test]
    fn helper_is_two() {
        assert_eq!(super::helper(), 2);
    }
}
