use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TextFingerprint {
    pub token_count: usize,
    pub unique_ratio: f64,
    pub entropy: f64,
    pub top_bigrams: Vec<(String, usize)>,
}

pub fn extract_text_fingerprint(text: &str) -> TextFingerprint {
    let tokens: Vec<String> = text
        .split_whitespace()
        .map(|token| {
            token
                .trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase()
        })
        .filter(|token| !token.is_empty())
        .collect();

    let unique = tokens.iter().collect::<HashSet<_>>().len();
    let mut frequencies: BTreeMap<&str, usize> = BTreeMap::new();
    for token in &tokens {
        *frequencies.entry(token).or_default() += 1;
    }
    let total = tokens.len().max(1) as f64;
    let entropy = frequencies.values().fold(0.0, |sum, count| {
        let probability = *count as f64 / total;
        sum - probability * probability.log2()
    });

    let mut bigrams: BTreeMap<String, usize> = BTreeMap::new();
    for pair in tokens.windows(2) {
        *bigrams
            .entry(format!("{} {}", pair[0], pair[1]))
            .or_default() += 1;
    }
    let mut top_bigrams: Vec<_> = bigrams.into_iter().collect();
    top_bigrams.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    top_bigrams.truncate(5);

    TextFingerprint {
        token_count: tokens.len(),
        unique_ratio: unique as f64 / total,
        entropy,
        top_bigrams,
    }
}

pub fn similarity(left: &TextFingerprint, right: &TextFingerprint) -> f64 {
    if left.token_count == 0 || right.token_count == 0 {
        return 0.0;
    }
    let token_ratio = left.token_count.min(right.token_count) as f64
        / left.token_count.max(right.token_count) as f64;
    let unique_delta = (left.unique_ratio - right.unique_ratio).abs().min(1.0);
    let entropy_scale = left.entropy.max(right.entropy).max(1.0);
    let entropy_delta = ((left.entropy - right.entropy).abs() / entropy_scale).min(1.0);
    let bigram_overlap = weighted_bigram_overlap(&left.top_bigrams, &right.top_bigrams);
    (token_ratio * 0.3
        + (1.0 - unique_delta) * 0.2
        + (1.0 - entropy_delta) * 0.2
        + bigram_overlap * 0.3)
        .clamp(0.0, 1.0)
}

fn weighted_bigram_overlap(left: &[(String, usize)], right: &[(String, usize)]) -> f64 {
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }

    let left: BTreeMap<&str, usize> = left
        .iter()
        .map(|(bigram, count)| (bigram.as_str(), *count))
        .collect();
    let right: BTreeMap<&str, usize> = right
        .iter()
        .map(|(bigram, count)| (bigram.as_str(), *count))
        .collect();
    let union = left.keys().chain(right.keys()).collect::<HashSet<_>>();
    let intersection_weight: usize = union
        .iter()
        .map(|bigram| {
            left.get(**bigram)
                .copied()
                .unwrap_or_default()
                .min(right.get(**bigram).copied().unwrap_or_default())
        })
        .sum();
    let union_weight: usize = union
        .iter()
        .map(|bigram| {
            left.get(**bigram)
                .copied()
                .unwrap_or_default()
                .max(right.get(**bigram).copied().unwrap_or_default())
        })
        .sum();

    if union_weight == 0 {
        0.0
    } else {
        intersection_weight as f64 / union_weight as f64
    }
}

#[cfg(test)]
mod tests {
    use super::{extract_text_fingerprint, similarity};

    #[test]
    fn identical_text_has_full_similarity() {
        let sample = extract_text_fingerprint("Evidence needs a stable protocol shape");
        assert!((similarity(&sample, &sample) - 1.0).abs() < f64::EPSILON);
        assert_eq!(sample.token_count, 6);
    }

    #[test]
    fn bigrams_distinguish_word_order() {
        let reference = extract_text_fingerprint("stable evidence supports reliable model checks");
        let structurally_similar =
            extract_text_fingerprint("stable evidence supports reliable provider checks");
        let reordered = extract_text_fingerprint("checks model reliable supports evidence stable");

        assert!(similarity(&reference, &structurally_similar) > similarity(&reference, &reordered));
    }

    #[test]
    fn similarity_is_symmetric_bounded_and_empty_safe() {
        let left = extract_text_fingerprint("one stable response shape");
        let right = extract_text_fingerprint("one different response shape");
        let empty = extract_text_fingerprint("");
        let forward = similarity(&left, &right);
        let backward = similarity(&right, &left);

        assert!((forward - backward).abs() < f64::EPSILON);
        assert!((0.0..=1.0).contains(&forward));
        assert_eq!(similarity(&left, &empty), 0.0);
        assert_eq!(similarity(&empty, &empty), 0.0);
    }
}
