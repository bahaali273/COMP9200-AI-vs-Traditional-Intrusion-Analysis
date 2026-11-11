# Operator tool: tabulate headline numbers from the three AI runs (not part of the AI arm).
# Reads the saved run outputs in ai-arm/runN/outputs/.
import json
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
ARM = HERE.parent
FEATS = ["dur", "sbytes", "dbytes", "spkts", "dpkts"]
r1 = pd.read_csv(ARM / "run1" / "outputs" / "rq1_rq2_feature_summary.csv")
r3 = pd.read_csv(ARM / "run3" / "outputs" / "rq1_summary.csv")
r2 = json.load(open(ARM / "run2" / "outputs" / "results.json"))

rows = []
for p in ("train", "test"):
    for f in FEATS:
        a = r1[(r1.partition == p) & (r1.feature == f)].iloc[0]
        c = r3[(r3.partition == p) & (r3["var"] == f)].iloc[0]
        b = r2["effects_" + p][f]
        rows.append(dict(partition=p, feature=f,
                         n_normal=int(a.n_normal), n_malicious=int(a.n_mal),
                         median_normal=a.med_normal, median_malicious=a.med_mal,
                         r_run1=a.cliffs_delta_mal_vs_normal, r_run2=b["rank_biserial"],
                         r_run3=c.cliffs_delta_mal_vs_normal,
                         p_run1=a.mwu_p, p_run2=b["mwu_p"], p_run3=c.mwu_p))
df = pd.DataFrame(rows)
r = df[["r_run1", "r_run2", "r_run3"]]
df["max_abs_r_diff_between_runs"] = r.max(axis=1) - r.min(axis=1)
pd.set_option("display.width", 250)
print(df.to_string())
df.to_csv(HERE / "cross_run_headline.csv", index=False)
print(json.dumps(r2["integrity"], indent=1, default=str))
