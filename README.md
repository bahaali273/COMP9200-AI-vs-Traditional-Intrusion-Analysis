# COMP 9200 — AI-Assisted vs. Independent Network Intrusion Analysis

## Project Overview

This research project investigates differences between generative AI-assisted data analysis and a reproducible Python-based statistical analysis of cybersecurity network traffic.

The study uses the publicly available UNSW-NB15 dataset to compare findings, analytical rigor, transparency, potential bias, and reproducibility.

**Course:** COMP 9200 — Applied Research Methods  
**Institution:** British Columbia Institute of Technology (BCIT)  
**Status:** Independent Python analysis completed; AI-assisted comparison pending.

## Research Questions

1. How do selected network traffic characteristics differ between normal and malicious traffic?
2. Do the observed differences remain consistent across the training and testing datasets?
3. How do generative AI-assisted findings compare with the Python-based analysis in accuracy of interpretation, rigor, transparency, bias, and reproducibility?

## Dataset

**Name:** UNSW-NB15  
**Source:** [University of New South Wales](https://research.unsw.edu.au/projects/unsw-nb15-dataset)

| Dataset | Records | Features / Columns |
|---|---:|---:|
| Training | 175,341 | 45 |
| Testing | 82,332 | 45 |

The analysis uses five numerical features:

- `dur` — Connection duration
- `sbytes` — Source bytes
- `dbytes` — Destination bytes
- `spkts` — Source packets
- `dpkts` — Destination packets

The `label` and `attack_cat` columns provide traffic classifications.

## Methodology

The independent Python workflow includes:

1. Dataset loading and inspection.
2. Missing-value and duplicate-record assessment.
3. Feature selection and validation.
4. Descriptive statistical analysis.
5. Distribution visualization.
6. Mann–Whitney U hypothesis testing.
7. Rank-biserial effect-size calculation.
8. Attack-category analysis.
9. Testing-dataset comparison.
10. Automated consistency checks.

Repeated feature records were retained in the primary analysis because identical values do not necessarily indicate erroneous observations.

## Preliminary Findings

- Malicious traffic represents approximately 68.06% of training records.
- No missing values were identified by Pandas.
- Malicious traffic has a lower median source-byte value than normal traffic in both dataset partitions.
- The Mann–Whitney U test produced p-values below 0.001 in both partitions.
- Rank-biserial effect sizes were −0.4134 for training and −0.3988 for testing.
- Different attack categories exhibit different traffic characteristics.

These findings are descriptive and exploratory, not evidence of causal relationships or intrusion detection model accuracy.

## Reproducing the Analysis

1. Download the training and testing CSV files from the official UNSW-NB15 dataset page.
2. Open `notebooks/01_dataset_exploration.ipynb` using Google Colab.
3. Upload the two CSV files to your own Google Drive.
4. Update the notebook's `data_path` to match your dataset location.
5. Run the notebook cells sequentially.

The analysis was performed using:

- Python (Google Colab)
- Pandas 2.2.3
- NumPy 2.4.6
- SciPy 1.16.3
- Matplotlib (version to be documented)

## Research Limitations

The dataset includes substantial repeated feature patterns and potentially dependent network observations. Statistical significance should therefore be interpreted cautiously.

The analysis uses historical benchmark data, and the findings may not generalize to live network environments.

## AI Use Disclosure

ChatGPT (OpenAI) assisted with Python code development, statistical explanations, interpretation, and documentation. The Python analysis was executed in Google Colab, and its outputs were inspected and recorded.

The planned AI-assisted analysis will be separately documented with prompts, outputs, and comparison criteria.

## Project Structure

```text
COMP9200-AI-vs-Traditional-Intrusion-Analysis/
├── README.md
├── .gitignore
└── notebooks/
    ├── README.md
    └── 01_dataset_exploration.ipynb
```

Additional analysis logs, results, and paper files will be added as the project progresses.

## References

UNSW-NB15 dataset, University of New South Wales. Official dataset page: https://research.unsw.edu.au/projects/unsw-nb15-dataset

The final IEEE paper will include the appropriate dataset research citations.
