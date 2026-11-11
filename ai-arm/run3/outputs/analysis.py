import pandas as pd, numpy as np, json, sys, platform
import scipy, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy import stats

files = ["UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"]
raw = {f: pd.read_csv(f) for f in files}
out = {"env": {"python": sys.version, "pandas": pd.__version__, "numpy": np.__version__,
               "scipy": scipy.__version__, "matplotlib": matplotlib.__version__, "os": platform.platform()}}
out["files"] = {f: {"rows": len(d), "cols": list(d.columns)} for f, d in raw.items()}

cols = ["dur", "sbytes", "dbytes", "spkts", "dpkts"]
# Identify partitions by contents (row count); the official train is the larger one
order = sorted(raw, key=lambda f: -len(raw[f]))
parts = {"train": raw[order[0]], "test": raw[order[1]]}
out["identified"] = {"train": order[0], "test": order[1]}

qa = {}
for k, d in parts.items():
    qa[k] = {"rows": len(d),
             "label_counts": d["label"].value_counts().to_dict(),
             "label_prop_malicious": float(d["label"].mean()),
             "attack_cat_counts": d["attack_cat"].value_counts().to_dict(),
             "missing_selected": d[cols + ["label"]].isna().sum().to_dict(),
             "negative_selected": {c: int((d[c] < 0).sum()) for c in cols},
             "zero_dur": int((d["dur"] == 0).sum()),
             "zero_dbytes": int((d["dbytes"] == 0).sum()),
             "dup_rows_excl_id": int(d.drop(columns=[c for c in ["id"] if c in d]).duplicated().sum())}
    # label / attack_cat consistency
    qa[k]["normal_label_mismatch"] = int(((d["attack_cat"] == "Normal") != (d["label"] == 0)).sum())
out["qa"] = qa

def cliff(x, y):
    # P(x>y)-P(x<y) via Mann-Whitney U
    u = stats.mannwhitneyu(x, y, alternative="two-sided")
    return 2 * u.statistic / (len(x) * len(y)) - 1, u.pvalue

rows = []
for k, d in parts.items():
    for c in cols:
        n, m = d.loc[d.label == 0, c], d.loc[d.label == 1, c]
        delta, p = cliff(m, n)  # positive => malicious larger
        rows.append({"partition": k, "var": c,
                     "n_normal": len(n), "n_mal": len(m),
                     "median_normal": n.median(), "median_mal": m.median(),
                     "q25_normal": n.quantile(.25), "q75_normal": n.quantile(.75),
                     "q25_mal": m.quantile(.25), "q75_mal": m.quantile(.75),
                     "mean_normal": n.mean(), "mean_mal": m.mean(),
                     "cliffs_delta_mal_vs_normal": delta, "mwu_p": p})
res = pd.DataFrame(rows)
res.to_csv("rq1_summary.csv", index=False)

# bootstrap CI for Cliff's delta (subsample for speed, fixed seed)
rng = np.random.default_rng(42)
bt = []
for k, d in parts.items():
    for c in cols:
        n = d.loc[d.label == 0, c].values; m = d.loc[d.label == 1, c].values
        ds = []
        for _ in range(200):
            a = rng.choice(m, 3000); b = rng.choice(n, 3000)
            ds.append(2 * stats.mannwhitneyu(a, b).statistic / (3000 * 3000) - 1)
        bt.append({"partition": k, "var": c, "ci_lo": np.percentile(ds, 2.5), "ci_hi": np.percentile(ds, 97.5)})
pd.DataFrame(bt).to_csv("rq1_cliff_bootstrap_ci.csv", index=False)

# RQ2: compare partitions
r2 = []
for c in cols:
    t = res[(res.partition == "train") & (res["var"] == c)].iloc[0]
    s = res[(res.partition == "test") & (res["var"] == c)].iloc[0]
    r2.append({"var": c, "delta_train": t.cliffs_delta_mal_vs_normal, "delta_test": s.cliffs_delta_mal_vs_normal,
               "same_direction": np.sign(t.cliffs_delta_mal_vs_normal) == np.sign(s.cliffs_delta_mal_vs_normal),
               "median_ratio_mal_over_normal_train": t.median_mal / t.median_normal if t.median_normal else np.nan,
               "median_ratio_mal_over_normal_test": s.median_mal / s.median_normal if s.median_normal else np.nan})
pd.DataFrame(r2).to_csv("rq2_consistency.csv", index=False)

# Same-class cross-partition shift (is the distribution of each class stable?)
sh = []
for lab, nm in [(0, "normal"), (1, "malicious")]:
    for c in cols:
        a = parts["train"].loc[parts["train"].label == lab, c]; b = parts["test"].loc[parts["test"].label == lab, c]
        ks = stats.ks_2samp(a, b)
        dl, _ = cliff(b, a)
        sh.append({"class": nm, "var": c, "ks_stat": ks.statistic, "ks_p": ks.pvalue, "cliffs_delta_test_vs_train": dl,
                   "median_train": a.median(), "median_test": b.median()})
pd.DataFrame(sh).to_csv("rq2_class_shift.csv", index=False)

# per attack category (medians + delta vs normal), per partition
ac = []
for k, d in parts.items():
    nrm = d[d.label == 0]
    for cat, g in d[d.label == 1].groupby("attack_cat"):
        for c in cols:
            dl, _ = cliff(g[c], nrm[c])
            ac.append({"partition": k, "attack_cat": cat, "n": len(g), "var": c,
                       "median": g[c].median(), "median_normal": nrm[c].median(), "cliffs_delta_vs_normal": dl})
acd = pd.DataFrame(ac); acd.to_csv("rq1_by_attack_cat.csv", index=False)
piv = acd.pivot_table(index=["attack_cat", "var"], columns="partition", values="cliffs_delta_vs_normal").reset_index()
piv["abs_diff"] = (piv.train - piv.test).abs()
piv.to_csv("rq2_attack_cat_consistency.csv", index=False)

# figures
fig, axs = plt.subplots(2, 5, figsize=(22, 8))
for i, (k, d) in enumerate(parts.items()):
    for j, c in enumerate(cols):
        data = [np.log10(d.loc[d.label == l, c] + 1e-6 if c == "dur" else d.loc[d.label == l, c] + 1) for l in (0, 1)]
        axs[i, j].boxplot(data, labels=["normal", "malicious"], showfliers=False)
        axs[i, j].set_title(f"{k}: log10({c}{'+1e-6' if c=='dur' else '+1'})")
plt.tight_layout(); plt.savefig("fig_boxplots.png", dpi=110); plt.close()

fig, ax = plt.subplots(figsize=(7, 4))
x = np.arange(len(cols))
ax.bar(x - .2, [r["delta_train"] for r in r2], .4, label="train")
ax.bar(x + .2, [r["delta_test"] for r in r2], .4, label="test")
ax.set_xticks(x); ax.set_xticklabels(cols); ax.axhline(0, c="k"); ax.legend()
ax.set_ylabel("Cliff's delta (malicious vs normal)"); plt.tight_layout(); plt.savefig("fig_effect_sizes.png", dpi=110); plt.close()

pd.set_option("display.width", 250); pd.set_option("display.max_columns", 50); pd.set_option("display.float_format", lambda v: f"{v:.4g}")
json.dump(out, open("results_meta.json", "w"), indent=2, default=str)
print(json.dumps(out, indent=1, default=str))
print(res.to_string()); print(pd.read_csv("rq1_cliff_bootstrap_ci.csv").to_string())
print(pd.read_csv("rq2_consistency.csv").to_string()); print(pd.read_csv("rq2_class_shift.csv").to_string())
print(piv.sort_values("abs_diff", ascending=False).head(12).to_string())
print("max abs diff", piv.abs_diff.max(), "sign flips", int(((np.sign(piv.train) != np.sign(piv.test)) & (piv.train.abs() > .1) & (piv.test.abs() > .1)).sum()))
