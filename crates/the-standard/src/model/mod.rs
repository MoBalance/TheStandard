use crate::{
    CORE_CAPABILITIES, CORE_CAPABILITY_PROFILE, CoreBuildInfo, Protocol, REPORT_SCHEMA_VERSION,
};

pub fn core_build_info() -> CoreBuildInfo {
    CoreBuildInfo {
        name: "TheStandard".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        report_schema_version: REPORT_SCHEMA_VERSION,
        capability_profile: CORE_CAPABILITY_PROFILE.into(),
        capabilities: CORE_CAPABILITIES
            .iter()
            .map(|capability| (*capability).into())
            .collect(),
        supported_protocols: vec![Protocol::Anthropic, Protocol::Openai, Protocol::Gemini],
    }
}

pub(crate) fn mask_api_key(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    match chars.len() {
        0 => String::new(),
        1..=6 => format!("{}{}", chars[0], "*".repeat(chars.len().saturating_sub(1))),
        len => format!(
            "{}{}{}",
            chars[..4].iter().collect::<String>(),
            "*".repeat(6),
            chars[len - 2..].iter().collect::<String>()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{core_build_info, mask_api_key};
    use crate::{CORE_CAPABILITIES, CORE_CAPABILITY_PROFILE, REPORT_SCHEMA_VERSION};

    #[test]
    fn core_build_info_is_self_describing() {
        let info = core_build_info();
        assert_eq!(info.name, "TheStandard");
        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(info.report_schema_version, REPORT_SCHEMA_VERSION);
        assert_eq!(info.capability_profile, CORE_CAPABILITY_PROFILE);
        assert_eq!(info.capabilities.len(), CORE_CAPABILITIES.len());
        assert_eq!(info.supported_protocols.len(), 3);
    }

    #[test]
    fn masks_secrets_without_exposing_the_middle() {
        assert_eq!(mask_api_key("sk-abcdefghij"), "sk-a******ij");
        assert_eq!(mask_api_key("short"), "s****");
        assert_eq!(mask_api_key(""), "");
    }
}
