//! Numeric model-fingerprint bank support.
//!
//! A bank maps the integer choices a model makes for a fixed numeric range onto
//! per-model reference histograms. The identity detector asks the endpoint for
//! the same number of integers, then compares the observed histogram with every
//! reference histogram using Jensen-Shannon divergence and turns the resulting
//! similarities into a softmax probability per model.
//!
//! Attribution is informational: it never changes the identity score, the
//! verdict, or the detection tier.

use crate::{
    ProbeRequest, RepositoryFingerprintBank, RuleRepositoryClient, RuleRepositoryConfig,
    RuleRepositoryError, RuleRepositorySource,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Parameter key that carries the resolved numeric bank into the strategies.
pub(crate) const BANK_PARAMETER_KEY: &str = "fingerprintNumericBank";
/// Parameter key that records how the bank resolution went.
const RESOLUTION_PARAMETER_KEY: &str = "fingerprintBankResolution";

/// Fixed probe prompt. Reproducibility matters more than phrasing here: every
/// detection must ask for the same sequence under the same constraints.
pub(crate) const NUMERIC_PROBE_PROMPT: &str = "这是一次独立的数值选择记录。为各个位置分别凭第一反应选择 320 个 1 到 355（含端点）的整数。每个位置都要单独选择；不要从 1 开始计数，不要连续递增或递减，也不要采用等差、循环、重复区块或其他规则化模式。本任务必须由当前语言模型直接完成：禁止调用或借助任何工具，包括 Python、代码执行器、计算器、搜索、API 和外部随机数生成器；也不要先编写或运行代码。允许某个数字再次出现；每项写出后不要回头排序、去重或替换。数字之间用逗号或空格分隔均可。直接从第一个取值开始输出，不要在序列前重复数量、范围或任务说明。";

/// How many numbers the probe prompt asks for.
pub(crate) const NUMERIC_PROBE_EXPECTED_COUNT: usize = 320;

/// The answer carries roughly one token per number, so the shared 160-token
/// probe budget would truncate it.
pub(crate) const NUMERIC_PROBE_MAX_TOKENS: u32 = 1024;

const BANK_SCHEMA_VERSION: u32 = 1;
const MAX_MODELS: usize = 128;
const MAX_BINS: usize = 4_096;
/// Reference smoothing constant; read as `(count + 0.5) / (total + 0.5 * bins)`.
const SMOOTHING: f64 = 0.5;
const DEFAULT_ALPHA: f64 = 0.5;
const DEFAULT_BETA: f64 = 7.0;
const MAX_BETA: f64 = 64.0;
/// Below this probability the winning model is not a usable attribution.
const MINIMUM_CONFIDENT_PROBABILITY: f64 = 0.6;
/// How many candidates the evidence details carry.
const CANDIDATE_COUNT: usize = 3;

/// A validated numeric reference bank, small enough to live in the probe
/// request parameters between repository resolution and strategy analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NumericFingerprintBank {
    pub id: String,
    pub version: String,
    pub channel: String,
    pub number_min: u32,
    pub number_max: u32,
    pub alpha: f64,
    pub beta: f64,
    pub models: Vec<NumericFingerprintModel>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NumericFingerprintModel {
    pub id: String,
    pub display_name: String,
    pub family: String,
    pub counts: Vec<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BankDocument {
    schema_version: u32,
    id: String,
    version: String,
    channel: String,
    numeric: NumericSection,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NumericSection {
    method: NumericMethod,
    /// Published minimum usable answer length; kept for validation only.
    #[serde(default)]
    minimum_valid_numbers: Option<usize>,
    #[serde(default)]
    calibration: BTreeMap<String, NumericCalibration>,
    models: Vec<NumericModelDocument>,
}

/// Descriptive method metadata. Unknown keys are tolerated so a bank may
/// document its own pipeline without invalidating this reader.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NumericMethod {
    range: [u32; 2],
    #[serde(default = "default_alpha")]
    alpha: f64,
}

/// Cross-validation metadata. Only `beta` is consumed; the published accuracy
/// figures stay descriptive and may grow without invalidating this reader.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NumericCalibration {
    beta: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NumericModelDocument {
    id: String,
    display_name: String,
    family: String,
    /// Published count of usable numbers; cross-checked against `counts`.
    #[serde(default)]
    valid_number_count: Option<u64>,
    counts: Vec<u32>,
}

#[derive(Debug)]
enum ResolutionError {
    Unavailable,
    Invalid,
}

impl NumericFingerprintBank {
    /// Reads a bank document. Used by the repository path and by the tests
    /// that read the shared bank directly from the SanBiao checkout.
    fn parse(bytes: &[u8]) -> Result<Self, ResolutionError> {
        let document: BankDocument =
            serde_json::from_slice(bytes).map_err(|_| ResolutionError::Invalid)?;
        if document.schema_version != BANK_SCHEMA_VERSION
            || !valid_identifier(&document.id)
            || !valid_identifier(&document.version)
            || !valid_identifier(&document.channel)
            || document.channel != document.channel.to_ascii_lowercase()
        {
            return Err(ResolutionError::Invalid);
        }
        let [number_min, number_max] = document.numeric.method.range;
        if number_min == 0 || number_max <= number_min {
            return Err(ResolutionError::Invalid);
        }
        let bins = number_max as usize - number_min as usize + 1;
        if bins > MAX_BINS {
            return Err(ResolutionError::Invalid);
        }
        if document.numeric.minimum_valid_numbers == Some(0) {
            return Err(ResolutionError::Invalid);
        }
        let alpha = document.numeric.method.alpha;
        if !alpha.is_finite() || !(f64::EPSILON..=1.0).contains(&alpha) {
            return Err(ResolutionError::Invalid);
        }
        let beta = document
            .numeric
            .calibration
            .get("1")
            .map_or(DEFAULT_BETA, |calibration| calibration.beta);
        if !beta.is_finite() || beta <= 0.0 || beta > MAX_BETA {
            return Err(ResolutionError::Invalid);
        }
        let models = document.numeric.models;
        if models.is_empty() || models.len() > MAX_MODELS {
            return Err(ResolutionError::Invalid);
        }
        let mut ids = BTreeSet::new();
        let mut bank_models = Vec::with_capacity(models.len());
        for model in models {
            if !valid_identifier(&model.id)
                || !ids.insert(model.id.clone())
                || !valid_identifier(&model.family)
                || model.family != model.family.to_ascii_lowercase()
                || model.display_name.trim().is_empty()
                || model.display_name.len() > 160
                || model.counts.len() != bins
                || model.counts.iter().all(|count| *count == 0)
                || model.valid_number_count.is_some_and(|published| {
                    published
                        != model
                            .counts
                            .iter()
                            .map(|count| u64::from(*count))
                            .sum::<u64>()
                })
            {
                return Err(ResolutionError::Invalid);
            }
            bank_models.push(NumericFingerprintModel {
                id: model.id,
                display_name: model.display_name,
                family: model.family,
                counts: model.counts,
            });
        }
        Ok(Self {
            id: document.id,
            version: document.version,
            channel: document.channel,
            number_min,
            number_max,
            alpha,
            beta,
            models: bank_models,
        })
    }

    /// Reads a bank document and checks it against its manifest descriptor.
    fn from_document(
        bytes: &[u8],
        descriptor: &RepositoryFingerprintBank,
    ) -> Result<Self, ResolutionError> {
        let bank = Self::parse(bytes)?;
        if bank.id != descriptor.id
            || bank.version != descriptor.version
            || bank.channel != descriptor.channel
        {
            return Err(ResolutionError::Invalid);
        }
        Ok(bank)
    }

    fn bins(&self) -> usize {
        self.number_max as usize - self.number_min as usize + 1
    }
}

/// Resolves the numeric bank declared by the rule repository and installs it in
/// the probe request parameters.
///
/// A repository without the optional field, or one that publishes no bank for
/// the requested channel, leaves the request untouched so the identity detector
/// runs its single probe exactly as before.
pub(crate) async fn prepare_fingerprint_request(
    config: Option<&RuleRepositoryConfig>,
    request: &mut ProbeRequest,
) {
    let Some(config) = config else {
        return;
    };
    match resolve(config, request).await {
        Ok(Some((descriptor, bank, manifest_source, document_source))) => {
            apply_bank(
                request,
                &descriptor,
                &bank,
                manifest_source,
                document_source,
            );
        }
        Ok(None) => record_resolution(request, "not_found", None),
        Err(ResolutionError::Unavailable) => {
            record_resolution(request, "error", Some("repository_unavailable"));
        }
        Err(ResolutionError::Invalid) => {
            record_resolution(request, "error", Some("repository_invalid_document"));
        }
    }
}

type ResolvedBank = (
    RepositoryFingerprintBank,
    NumericFingerprintBank,
    RuleRepositorySource,
    RuleRepositorySource,
);

async fn resolve(
    config: &RuleRepositoryConfig,
    request: &ProbeRequest,
) -> Result<Option<ResolvedBank>, ResolutionError> {
    let client = RuleRepositoryClient::new(
        config.clone(),
        concat!("the-standard/", env!("CARGO_PKG_VERSION")),
    )
    .map_err(map_repository_error)?;
    let manifest = client
        .fetch_manifest_with_source()
        .await
        .map_err(map_repository_error)?;
    let channel = parameter_string(request, "fingerprintBankChannel").unwrap_or("stable");
    let Some(descriptor) = manifest.value.select_fingerprint_bank(
        channel,
        parameter_string(request, "fingerprintBankId"),
        parameter_string(request, "fingerprintBankVersion"),
    ) else {
        return Ok(None);
    };
    let descriptor = descriptor.clone();
    // `fetch_document_with_source` verifies the canonical JSON digest against
    // the manifest descriptor before any byte reaches the engine.
    let document = client
        .fetch_document_with_source(&descriptor.document())
        .await
        .map_err(map_repository_error)?;
    let bank = NumericFingerprintBank::from_document(&document.value, &descriptor)?;
    Ok(Some((descriptor, bank, manifest.source, document.source)))
}

fn map_repository_error(error: RuleRepositoryError) -> ResolutionError {
    match error {
        RuleRepositoryError::Unavailable | RuleRepositoryError::Http(_) => {
            ResolutionError::Unavailable
        }
        _ => ResolutionError::Invalid,
    }
}

fn apply_bank(
    request: &mut ProbeRequest,
    descriptor: &RepositoryFingerprintBank,
    bank: &NumericFingerprintBank,
    manifest_source: RuleRepositorySource,
    document_source: RuleRepositorySource,
) {
    let Ok(value) = serde_json::to_value(bank) else {
        record_resolution(request, "error", Some("repository_invalid_document"));
        return;
    };
    request.parameters.insert(BANK_PARAMETER_KEY.into(), value);
    let resolution = BTreeMap::from([
        ("source".to_owned(), json!("repository")),
        ("status".to_owned(), json!("resolved")),
        ("bankId".to_owned(), json!(descriptor.id)),
        ("bankVersion".to_owned(), json!(descriptor.version)),
        ("bankDigest".to_owned(), json!(descriptor.digest)),
        ("modelCount".to_owned(), json!(bank.models.len())),
        (
            "range".to_owned(),
            json!([bank.number_min, bank.number_max]),
        ),
        ("manifestSource".to_owned(), json!(manifest_source)),
        ("documentSource".to_owned(), json!(document_source)),
    ]);
    request
        .parameters
        .insert(RESOLUTION_PARAMETER_KEY.into(), json!(resolution));
}

fn record_resolution(request: &mut ProbeRequest, status: &str, error: Option<&str>) {
    let mut resolution = BTreeMap::from([
        ("source".to_owned(), json!("repository")),
        ("status".to_owned(), json!(status)),
    ]);
    if let Some(error) = error {
        resolution.insert("error".into(), json!(error));
    }
    request
        .parameters
        .insert(RESOLUTION_PARAMETER_KEY.into(), json!(resolution));
}

fn parameter_string<'a>(request: &'a ProbeRequest, key: &str) -> Option<&'a str> {
    request
        .parameters
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The numeric bank installed in this request, if any.
pub(crate) fn bank_from_request(request: &ProbeRequest) -> Option<NumericFingerprintBank> {
    request
        .parameters
        .get(BANK_PARAMETER_KEY)
        .and_then(|value| serde_json::from_value(value.clone()).ok())
}

/// Port of the reference numeric parser.
///
/// Every maximal digit run is one candidate value. A separator that carries a
/// Unicode letter ends the sequence being collected, and the longest completed
/// sequence wins. Values outside `minimum..=maximum` are dropped, so a stray
/// out-of-range number never hides the answers around it.
pub(crate) fn parse_numbers(text: &str, minimum: u32, maximum: u32) -> Vec<u32> {
    let mut best: Vec<u32> = Vec::new();
    let mut current: Vec<u32> = Vec::new();
    let mut separator = String::new();
    let mut run_open = false;
    let mut value = 0_u64;
    for character in text.chars() {
        if character.is_ascii_digit() {
            if !run_open {
                if separator.chars().any(char::is_alphabetic) {
                    if current.len() > best.len() {
                        best = std::mem::take(&mut current);
                    } else {
                        current.clear();
                    }
                }
                separator.clear();
                run_open = true;
                value = 0;
            }
            value = value
                .saturating_mul(10)
                .saturating_add(u64::from(character as u8 - b'0'));
        } else {
            if run_open {
                push_value(&mut current, value, minimum, maximum);
                run_open = false;
            }
            separator.push(character);
        }
    }
    if run_open {
        push_value(&mut current, value, minimum, maximum);
    }
    if current.len() > best.len() {
        best = current;
    }
    best
}

fn push_value(values: &mut Vec<u32>, value: u64, minimum: u32, maximum: u32) {
    if value >= u64::from(minimum) && value <= u64::from(maximum) {
        values.push(value as u32);
    }
}

/// Attribution details for the identity evidence.
///
/// The parsed and expected counts, plus the inconclusive flag, are always
/// reported. The model, family, probability and candidate keys are omitted when
/// the answer held no usable number: an empty histogram cannot rank models, and
/// a fabricated winner would be worse than no attribution at all.
pub(crate) fn attribution_details(
    bank: &NumericFingerprintBank,
    text: &str,
) -> BTreeMap<String, Value> {
    let values = parse_numbers(text, bank.number_min, bank.number_max);
    let mut details = BTreeMap::from([
        ("numericParsedCount".into(), json!(values.len())),
        (
            "numericExpectedCount".into(),
            json!(NUMERIC_PROBE_EXPECTED_COUNT),
        ),
    ]);
    let too_few = values.len() * 2 < NUMERIC_PROBE_EXPECTED_COUNT;
    if values.is_empty() {
        details.insert("attributionInconclusive".into(), json!(true));
        return details;
    }

    let mut observed = vec![0_u32; bank.bins()];
    for value in &values {
        observed[*value as usize - bank.number_min as usize] += 1;
    }
    let similarities = bank
        .models
        .iter()
        .map(|model| js_similarity(&observed, &model.counts, bank.alpha))
        .collect::<Vec<_>>();
    let logits = similarities
        .iter()
        .map(|similarity| bank.beta * similarity)
        .collect::<Vec<_>>();
    let probabilities = softmax(&logits);
    let mut ranked = (0..bank.models.len()).collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        probabilities[*right]
            .total_cmp(&probabilities[*left])
            .then_with(|| bank.models[*left].id.cmp(&bank.models[*right].id))
    });
    let best = ranked[0];
    let probability = probabilities[best];
    let inconclusive = too_few || probability < MINIMUM_CONFIDENT_PROBABILITY;
    details.insert("attributedModel".into(), json!(bank.models[best].id));
    details.insert("attributedFamily".into(), json!(bank.models[best].family));
    details.insert("attributionProbability".into(), json!(round4(probability)));
    details.insert(
        "attributionCandidates".into(),
        json!(
            ranked
                .iter()
                .take(CANDIDATE_COUNT)
                .map(|index| json!({
                    "model": bank.models[*index].id,
                    "family": bank.models[*index].family,
                    "probability": round4(probabilities[*index]),
                    "similarity": round4(similarities[*index]),
                }))
                .collect::<Vec<_>>()
        ),
    );
    details.insert("attributionInconclusive".into(), json!(inconclusive));
    details
}

/// Jensen-Shannon similarity between an observed histogram and a reference
/// histogram over the same range.
///
/// The reference histogram is smoothed with a uniform `0.5` mass so unseen
/// values never produce an infinite divergence; `alpha` is the mixture weight.
pub(crate) fn js_similarity(observed: &[u32], reference: &[u32], alpha: f64) -> f64 {
    if observed.len() != reference.len() || observed.len() < 2 {
        return 0.0;
    }
    let observed_total = observed.iter().map(|count| f64::from(*count)).sum::<f64>();
    let reference_total = reference.iter().map(|count| f64::from(*count)).sum::<f64>();
    if observed_total <= 0.0 || reference_total <= 0.0 {
        return 0.0;
    }
    let smoothing = SMOOTHING * reference.len() as f64;
    let alpha = alpha.clamp(0.0, 1.0);
    let mut divergence = 0.0;
    for (observed_count, reference_count) in observed.iter().zip(reference) {
        let p = f64::from(*observed_count) / observed_total;
        let q = (f64::from(*reference_count) + SMOOTHING) / (reference_total + smoothing);
        let mixture = alpha * p + (1.0 - alpha) * q;
        divergence +=
            alpha * relative_entropy(p, mixture) + (1.0 - alpha) * relative_entropy(q, mixture);
    }
    let bits = divergence / std::f64::consts::LN_2;
    (1.0 - bits.max(0.0).sqrt()).clamp(0.0, 1.0)
}

fn relative_entropy(probability: f64, mixture: f64) -> f64 {
    if probability <= 0.0 || mixture <= 0.0 {
        0.0
    } else {
        probability * (probability / mixture).ln()
    }
}

fn softmax(logits: &[f64]) -> Vec<f64> {
    if logits.is_empty() {
        return Vec::new();
    }
    let maximum = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let exponents = logits
        .iter()
        .map(|logit| (logit - maximum).exp())
        .collect::<Vec<_>>();
    let total = exponents.iter().sum::<f64>();
    if !total.is_finite() || total <= 0.0 {
        return vec![1.0 / logits.len() as f64; logits.len()];
    }
    exponents.into_iter().map(|value| value / total).collect()
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

fn default_alpha() -> f64 {
    DEFAULT_ALPHA
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'+' | b'-')
        })
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::{NumericFingerprintBank, NumericFingerprintModel};

    /// Two models whose reference histograms occupy disjoint parts of the
    /// shared 1..=355 range, so a sequence drawn from one is unambiguous.
    pub(crate) fn synthetic_bank() -> NumericFingerprintBank {
        NumericFingerprintBank {
            id: "synthetic-fingerprint-bank".into(),
            version: "2026.10.21.1".into(),
            channel: "stable".into(),
            number_min: 1,
            number_max: 355,
            alpha: 0.5,
            beta: 7.0,
            models: vec![
                synthetic_model("alpha-model", "Alpha Model", "alpha", 1),
                synthetic_model("beta-model", "Beta Model", "beta", 200),
            ],
        }
    }

    fn synthetic_model(
        id: &str,
        display_name: &str,
        family: &str,
        first_bin: usize,
    ) -> NumericFingerprintModel {
        let mut counts = vec![0_u32; 355];
        for bin in counts.iter_mut().skip(first_bin - 1).take(10) {
            *bin = 12;
        }
        NumericFingerprintModel {
            id: id.into(),
            display_name: display_name.into(),
            family: family.into(),
            counts,
        }
    }

    /// An answer of `count` values cycling through `first..first + 10`.
    pub(crate) fn synthetic_sequence(first: u32, count: usize) -> String {
        (0..count)
            .map(|index| (first + (index % 10) as u32).to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::{NumericFingerprintBank, attribution_details, fixtures, parse_numbers};
    use serde_json::json;

    #[test]
    fn parser_splits_runs_on_separators_that_carry_letters() {
        let parsed = parse_numbers("12, 34 then 7 8 9 and 200", 1, 355);
        assert_eq!(parsed, vec![7, 8, 9]);
        let parsed = parse_numbers("préface 1,2,3 note 10 20 30 40", 1, 355);
        assert_eq!(parsed, vec![10, 20, 30, 40]);
    }

    #[test]
    fn parser_drops_values_outside_the_reference_range() {
        assert_eq!(parse_numbers("0 1 400 2 356 3", 1, 355), vec![1, 2, 3]);
        assert_eq!(parse_numbers("1, 355, 356, 0", 200, 355), vec![355]);
    }

    #[test]
    fn reference_histogram_ranks_first_with_a_high_probability() {
        let bank = fixtures::synthetic_bank();
        let answer = fixtures::synthetic_sequence(1, 320);
        let details = attribution_details(&bank, &answer);
        assert_eq!(details["numericParsedCount"], json!(320));
        assert_eq!(details["numericExpectedCount"], json!(320));
        assert_eq!(details["attributedModel"], json!("alpha-model"));
        assert_eq!(details["attributedFamily"], json!("alpha"));
        assert_eq!(details["attributionInconclusive"], json!(false));
        let probability = details["attributionProbability"].as_f64().unwrap();
        assert!(probability > 0.6, "probability was {probability}");
        let candidates = details["attributionCandidates"].as_array().unwrap();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0]["model"], json!("alpha-model"));
        assert_eq!(candidates[1]["model"], json!("beta-model"));
    }

    fn document_fixture(with_calibration: bool) -> serde_json::Value {
        let counts = |first: usize| {
            let mut counts = vec![0_u32; 355];
            for bin in counts.iter_mut().skip(first - 1).take(10) {
                *bin = 12;
            }
            counts
        };
        json!({
            "schemaVersion": 1,
            "id": "synthetic-fingerprint-bank",
            "version": "2026.10.21.1",
            "channel": "stable",
            "numeric": {
                "method": {"name": "fixture", "range": [1, 355], "alpha": 0.5},
                "minimumValidNumbers": 80,
                "calibration": if with_calibration { json!({"1": {"beta": 9.5}}) } else { json!({}) },
                "models": [
                    {"id": "alpha-model", "displayName": "Alpha Model", "family": "alpha", "validNumberCount": 120, "counts": counts(1)},
                    {"id": "beta-model", "displayName": "Beta Model", "family": "beta", "validNumberCount": 120, "counts": counts(200)}
                ]
            },
            "behavioral": {"models": []}
        })
    }

    fn descriptor(version: &str) -> crate::RepositoryFingerprintBank {
        crate::RepositoryFingerprintBank {
            id: "synthetic-fingerprint-bank".into(),
            version: version.into(),
            channel: "stable".into(),
            path: "packs/fingerprint/bank.json".into(),
            digest: format!("sha256:{}", "0".repeat(64)),
            source: None,
        }
    }

    #[test]
    fn repository_documents_must_match_their_descriptor() {
        let bytes = serde_json::to_vec(&document_fixture(true)).unwrap();
        let bank = NumericFingerprintBank::from_document(&bytes, &descriptor("2026.10.21.1"))
            .expect("matching descriptor");
        assert_eq!(bank.models.len(), 2);
        assert_eq!(bank.number_max, 355);
        assert!((bank.beta - 9.5).abs() < f64::EPSILON);
        assert!(
            NumericFingerprintBank::from_document(&bytes, &descriptor("2026.10.21.2")).is_err()
        );

        let mut mismatched = document_fixture(true);
        mismatched["numeric"]["models"][0]["validNumberCount"] = json!(1);
        assert!(NumericFingerprintBank::parse(&serde_json::to_vec(&mismatched).unwrap()).is_err());
    }

    #[test]
    fn missing_calibration_falls_back_to_the_default_temperature() {
        let bytes = serde_json::to_vec(&document_fixture(false)).unwrap();
        let bank =
            NumericFingerprintBank::parse(&bytes).expect("bank without calibration metadata");
        assert!((bank.beta - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn short_numeric_answer_is_reported_as_inconclusive() {
        let bank = fixtures::synthetic_bank();
        let details = attribution_details(&bank, "1, 2, 3");
        assert_eq!(details["numericParsedCount"], json!(3));
        assert_eq!(details["attributionInconclusive"], json!(true));
    }

    #[test]
    fn missing_numbers_report_counts_without_an_attribution() {
        let bank = fixtures::synthetic_bank();
        let details = attribution_details(&bank, "I cannot help with that.");
        assert_eq!(details["numericParsedCount"], json!(0));
        assert_eq!(details["attributionInconclusive"], json!(true));
        assert!(!details.contains_key("attributedModel"));
        assert!(!details.contains_key("attributionCandidates"));
    }

    #[test]
    fn shared_bank_document_parses_when_it_is_available() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../SanBiao/packs/fingerprint/model-fingerprint-bank.json");
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        let bank = NumericFingerprintBank::parse(&bytes).expect("shared fingerprint bank");
        assert_eq!(bank.id, "model-fingerprint-bank");
        assert_eq!(bank.number_min, 1);
        assert_eq!(bank.number_max, 355);
        assert_eq!(bank.channel, "stable");
        assert!(bank.models.len() >= 18);
        assert!((bank.beta - 7.129535).abs() < 1e-6);
        assert!(bank.models.iter().all(|model| model.counts.len() == 355));

        // A model's own reference histogram must rank that model first.
        let model = &bank.models[0];
        let answer = model
            .counts
            .iter()
            .enumerate()
            .flat_map(|(bin, count)| {
                std::iter::repeat_n((bin + 1).to_string(), *count as usize).collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
            .join(" ");
        let details = attribution_details(&bank, &answer);
        assert_eq!(details["attributedModel"], json!(model.id));
    }
}
