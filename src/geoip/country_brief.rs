pub fn get_brief_name(code: &str) -> Option<&'static str> {
    match code {
        "AG" => Some("Antigua & Barbuda"),
        "BO" => Some("Bolivia"),
        "BQ" => Some("Bonaire, Statia & Saba"),
        "BA" => Some("Bosnia & Herzegovina"),
        "IO" => Some("Brit. Indian Ocean Terr."),
        "BN" => Some("Brunei"),
        "CV" => Some("Cape Verde"),
        "CD" => Some("DR Congo"),
        "CI" => Some("Ivory Coast"),
        "FK" => Some("Falkland Islands"),
        "VA" => Some("Vatican City"),
        "IR" => Some("Iran"),
        "KP" => Some("North Korea"),
        "KR" => Some("South Korea"),
        "LA" => Some("Laos"),
        "MO" => Some("Macau"),
        "FM" => Some("Micronesia"),
        "MD" => Some("Moldova"),
        "NL" => Some("Netherlands"),
        "PS" => Some("Palestine"),
        "RU" => Some("Russia"),
        "BL" => Some("St. Barthelemy"),
        "KN" => Some("St. Kitts & Nevis"),
        "LC" => Some("St. Lucia"),
        "MF" => Some("St. Martin"),
        "PM" => Some("St. Pierre & Miquelon"),
        "VC" => Some("St. Vincent & Grenadines"),
        "ST" => Some("Sao Tome & Principe"),
        "SX" => Some("Sint Maarten"),
        "SJ" => Some("Svalbard & Jan Mayen"),
        "SY" => Some("Syria"),
        "TW" => Some("Taiwan, China"),
        "TZ" => Some("Tanzania"),
        "TL" => Some("East Timor"),
        "TT" => Some("Trinidad & Tobago"),
        "TR" => Some("Turkey"),
        "TC" => Some("Turks & Caicos Islands"),
        "GB" => Some("United Kingdom"),
        "UM" => Some("US Minor Outlying Is."),
        "US" => Some("United States"),
        "VE" => Some("Venezuela"),
        "VN" => Some("Vietnam"),
        "VG" => Some("British Virgin Is."),
        "VI" => Some("US Virgin Is."),
        "WF" => Some("Wallis & Futuna"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_brief_name() {
        assert_eq!(get_brief_name("US"), Some("United States"));
        assert_eq!(get_brief_name("KR"), Some("South Korea"));
        assert_eq!(get_brief_name("XX"), None);
    }
}
