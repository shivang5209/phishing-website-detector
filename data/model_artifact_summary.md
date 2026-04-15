# Training Summary

- Selected model: `logistic_regression`
- Dataset mode: `raw_url`
- Threshold: `0.5`
- Training rows: `12`
- Test rows: `3`
- Feature count: `32`

## Data Sources

- `data\sample_urls.csv`

## Model Comparison

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
| --- | ---: | ---: | ---: | ---: | ---: |
| logistic_regression | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| random_forest | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| xgboost | 0.3333 | 0.3333 | 1.0000 | 0.5000 | 0.5000 |

## Feature Order

`url_length`, `hostname_length`, `path_length`, `query_length`, `subdomain_count`, `dot_count`, `hyphen_count`, `underscore_count`, `slash_count`, `question_mark_count`, `equals_count`, `at_symbol_present`, `https_scheme`, `ip_address_host`, `digit_ratio`, `url_entropy`, `suspicious_tld`, `shortener_domain`, `phishing_keyword_count_url`, `brand_in_subdomain`, `dns_resolves`, `ssl_available`, `ssl_days_remaining`, `domain_age_days`, `page_fetch_success`, `form_count`, `password_field_count`, `iframe_count`, `script_count`, `external_link_ratio`, `title_brand_mismatch`, `phishing_keyword_count_content`
