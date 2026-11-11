# Operator tool: two extra checks used in the comparison (not part of the AI arm).
# 1) Reproduce the baseline notebook's sbytes U statistics with local library versions.
# 2) Test the AI runs' untested claim that the pooled effect is "driven by" Generic traffic.
# Data folder: environment variable UNSW_DATA, default ../data next to the repository.
import os
from pathlib import Path

import pandas as pd
from scipy.stats import mannwhitneyu

HERE = Path(__file__).resolve().parent
D = Path(os.environ.get("UNSW_DATA", HERE.parents[2] / "data"))
P = {"train": pd.read_csv(D / "UNSW_NB15_training-set.csv"),
     "test": pd.read_csv(D / "UNSW_NB15_testing-set.csv")}
F = ["dur", "sbytes", "dbytes", "spkts", "dpkts"]


def rb(x, y):
    return 2 * mannwhitneyu(x, y).statistic / (len(x) * len(y)) - 1


print("1) Baseline sbytes U statistic (baseline notebook: train 1960253092.50, test 504205113.00)")
for p, d in P.items():
    u = mannwhitneyu(d.loc[d.label == 1, "sbytes"], d.loc[d.label == 0, "sbytes"],
                     alternative="two-sided", method="asymptotic")
    print(f"   {p}: U = {u.statistic:.2f}, p = {u.pvalue:.6e}")

print("\n2) Pooled effect with and without Generic (malicious vs normal)")
rows = []
for p, d in P.items():
    n = d[d.label == 0]
    m_all = d[d.label == 1]
    m_ng = m_all[m_all.attack_cat != "Generic"]
    for f in F:
        rows.append(dict(partition=p, feature=f, r_all_malicious=rb(m_all[f], n[f]),
                         r_excluding_generic=rb(m_ng[f], n[f]),
                         generic_share_of_malicious=(m_all.attack_cat == "Generic").mean()))
out = pd.DataFrame(rows)
out["change"] = out.r_excluding_generic - out.r_all_malicious
pd.set_option("display.width", 200)
print(out.round(3).to_string(index=False))
out.to_csv(HERE / "generic_sensitivity.csv", index=False)
