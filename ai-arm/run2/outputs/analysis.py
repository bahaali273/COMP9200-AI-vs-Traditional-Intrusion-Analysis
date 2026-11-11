import sys, platform, json
import pandas as pd, numpy as np, scipy, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy import stats

files = ["UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"]
raw = {f: pd.read_csv(f) for f in files}
out = {"env": {"python": sys.version, "platform": platform.platform(), "pandas": pd.__version__,
               "numpy": np.__version__, "scipy": scipy.__version__, "matplotlib": matplotlib.__version__}}
cols = ["dur", "sbytes", "dbytes", "spkts", "dpkts"]

# identify partitions from contents (row counts)
out["shapes"] = {f: list(d.shape) for f, d in raw.items()}
# the larger file is the "training" partition by content; record whether names agree
big = max(raw, key=lambda f: len(raw[f]))
small = min(raw, key=lambda f: len(raw[f]))
train, test = raw[big], raw[small]
out["train_file_by_content"] = big; out["test_file_by_content"] = small
out["integrity"] = {}
for n, d in (("train", train), ("test", test)):
    out["integrity"][n] = {
        "rows": len(d), "missing_in_cols": int(d[cols + ["label", "attack_cat"]].isna().sum().sum()),
        "negative_values": int((d[cols] < 0).sum().sum()),
        "label_counts": d["label"].value_counts().to_dict(),
        "attack_cat_counts": d["attack_cat"].value_counts().to_dict(),
        "dup_rows_excluding_id": int(d.drop(columns=[c for c in ["id"] if c in d]).duplicated().sum()),
        "zero_dbytes_share_by_label": d.groupby("label")["dbytes"].apply(lambda s: float((s == 0).mean())).to_dict(),
    }
out["integrity"]["id_overlap"] = int(len(set(train["id"]) & set(test["id"]))) if "id" in train else None
key = [c for c in train.columns if c not in ("id", "label", "attack_cat")]
out["integrity"]["exact_feature_row_overlap"] = int(len(train[key].drop_duplicates().merge(test[key].drop_duplicates(), on=key)))

def desc(d):
    r = {}
    for c in cols:
        for l, g in d.groupby("label"):
            x = g[c]
            r[f"{c}|label={l}"] = dict(n=len(x), mean=x.mean(), median=x.median(), q25=x.quantile(.25), q75=x.quantile(.75), q95=x.quantile(.95), max=x.max())
    return r

def effects(d):
    r = {}
    for c in cols:
        a = d.loc[d.label == 0, c].values; b = d.loc[d.label == 1, c].values
        u = stats.mannwhitneyu(b, a, alternative="two-sided")
        cles = u.statistic / (len(a) * len(b))  # P(malicious > normal) + 0.5 ties
        rbc = 2 * cles - 1
        # bootstrap CI for median difference (log-scale ratio not used; raw difference)
        rng = np.random.default_rng(0)
        diffs = [np.median(rng.choice(b, len(b))) - np.median(rng.choice(a, len(a))) for _ in range(500)]
        r[c] = dict(median_normal=float(np.median(a)), median_malicious=float(np.median(b)),
                    median_diff=float(np.median(b) - np.median(a)),
                    median_diff_ci95=[float(np.percentile(diffs, 2.5)), float(np.percentile(diffs, 97.5))],
                    mwu_p=float(u.pvalue), prob_mal_gt_normal=float(cles), rank_biserial=float(rbc))
    return r

out["desc_train"] = desc(train); out["desc_test"] = desc(test)
out["effects_train"] = effects(train); out["effects_test"] = effects(test)

# consistency: sign agreement, and normal-vs-normal / mal-vs-mal cross-partition shifts
cons = {}
for c in cols:
    et, es = out["effects_train"][c], out["effects_test"][c]
    row = dict(rbc_train=et["rank_biserial"], rbc_test=es["rank_biserial"],
               same_direction=bool(np.sign(et["rank_biserial"]) == np.sign(es["rank_biserial"])),
               rbc_abs_diff=abs(et["rank_biserial"] - es["rank_biserial"]))
    for l, nm in ((0, "normal"), (1, "malicious")):
        a = train.loc[train.label == l, c]; b = test.loc[test.label == l, c]
        u = stats.mannwhitneyu(b, a)
        row[f"{nm}_test_vs_train_prob_greater"] = float(u.statistic / (len(a) * len(b)))
        row[f"{nm}_median_train"] = float(a.median()); row[f"{nm}_median_test"] = float(b.median())
    cons[c] = row
out["consistency"] = cons

# per attack category (log-median) both partitions
cat = {}
for n, d in (("train", train), ("test", test)):
    cat[n] = d.groupby("attack_cat")[cols].median().to_dict("index")
out["cat_medians"] = cat
catrbc = {}
for n, d in (("train", train), ("test", test)):
    nm = d[d.label == 0]
    catrbc[n] = {}
    for k, g in d[d.label == 1].groupby("attack_cat"):
        catrbc[n][k] = {c: float(2 * stats.mannwhitneyu(g[c], nm[c]).statistic / (len(g) * len(nm)) - 1) for c in cols}
out["cat_rank_biserial_vs_normal"] = catrbc

json.dump(out, open("results.json", "w"), indent=1, default=float)
pd.DataFrame(cons).T.to_csv("consistency_table.csv")
pd.DataFrame({n: pd.DataFrame(out["effects_" + n]).T.stack() for n in ("train", "test")}).to_csv("effects_table.csv")

# figures
fig, ax = plt.subplots(2, 5, figsize=(20, 7), sharey="row")
for i, (n, d) in enumerate((("train", train), ("test", test))):
    for j, c in enumerate(cols):
        data = [np.log10(d.loc[d.label == l, c] + 1e-6 if c == "dur" else d.loc[d.label == l, c] + 1) for l in (0, 1)]
        ax[i, j].boxplot(data, labels=["normal", "malicious"], showfliers=False)
        ax[i, j].set_title(f"{n}: log10({c}{'+1e-6' if c=='dur' else '+1'})")
plt.tight_layout(); plt.savefig("fig_boxplots_by_partition.png", dpi=110); plt.close()
fig, ax = plt.subplots(figsize=(7, 4))
x = np.arange(len(cols))
ax.bar(x - .2, [cons[c]["rbc_train"] for c in cols], .4, label="train")
ax.bar(x + .2, [cons[c]["rbc_test"] for c in cols], .4, label="test")
ax.set_xticks(x); ax.set_xticklabels(cols); ax.axhline(0, c="k"); ax.legend()
ax.set_ylabel("rank-biserial (malicious vs normal)")
plt.tight_layout(); plt.savefig("fig_effect_consistency.png", dpi=110); plt.close()
print(json.dumps({k: out[k] for k in ["shapes", "train_file_by_content", "integrity", "effects_train", "effects_test", "consistency"]}, indent=1, default=float))
