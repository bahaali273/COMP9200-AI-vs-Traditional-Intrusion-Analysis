import pandas as pd, numpy as np, json, sys, platform
import scipy, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.stats import mannwhitneyu, ks_2samp

F = ['dur', 'sbytes', 'dbytes', 'spkts', 'dpkts']
parts = {'train': pd.read_csv('UNSW_NB15_training-set.csv'),
         'test': pd.read_csv('UNSW_NB15_testing-set.csv')}
out = {'env': {'python': sys.version, 'pandas': pd.__version__, 'numpy': np.__version__,
               'scipy': scipy.__version__, 'matplotlib': matplotlib.__version__, 'os': platform.platform()}}

def cliff(a, b):
    # P(mal > normal) based effect: cliff's delta from Mann-Whitney U
    u = mannwhitneyu(a, b).statistic
    return 2 * u / (len(a) * len(b)) - 1

rows = []
for p, d in parts.items():
    for f in F:
        n, m = d.loc[d.label == 0, f], d.loc[d.label == 1, f]
        rows.append(dict(partition=p, feature=f, n_normal=len(n), n_mal=len(m),
                         med_normal=n.median(), med_mal=m.median(),
                         mean_normal=n.mean(), mean_mal=m.mean(),
                         q25_normal=n.quantile(.25), q75_normal=n.quantile(.75),
                         q25_mal=m.quantile(.25), q75_mal=m.quantile(.75),
                         zero_frac_normal=(n == 0).mean(), zero_frac_mal=(m == 0).mean(),
                         cliffs_delta_mal_vs_normal=cliff(m, n),
                         mwu_p=mannwhitneyu(m, n).pvalue))
res = pd.DataFrame(rows)
res.to_csv('rq1_rq2_feature_summary.csv', index=False)

# RQ2: consistency of direction/effect size, and train vs test shift within class
cons = []
for f in F:
    a = res[(res.partition == 'train') & (res.feature == f)].iloc[0]
    b = res[(res.partition == 'test') & (res.feature == f)].iloc[0]
    r = dict(feature=f, delta_train=a.cliffs_delta_mal_vs_normal, delta_test=b.cliffs_delta_mal_vs_normal,
             same_direction=np.sign(a.cliffs_delta_mal_vs_normal) == np.sign(b.cliffs_delta_mal_vs_normal),
             med_ratio_train=(a.med_mal / a.med_normal) if a.med_normal else np.nan,
             med_ratio_test=(b.med_mal / b.med_normal) if b.med_normal else np.nan)
    for lab, nm in [(0, 'normal'), (1, 'mal')]:
        x = parts['train'].loc[parts['train'].label == lab, f]
        y = parts['test'].loc[parts['test'].label == lab, f]
        r[f'ks_stat_train_vs_test_{nm}'] = ks_2samp(x, y).statistic
        r[f'cliffs_delta_test_vs_train_{nm}'] = cliff(y, x)
    cons.append(r)
pd.DataFrame(cons).to_csv('rq2_consistency.csv', index=False)

# Per-attack-category medians and effect vs normal
cat = []
for p, d in parts.items():
    nrm = d[d.label == 0]
    for c, g in d[d.label == 1].groupby('attack_cat'):
        for f in F:
            cat.append(dict(partition=p, attack_cat=c, n=len(g), feature=f, median=g[f].median(),
                            median_normal=nrm[f].median(), cliffs_delta_vs_normal=cliff(g[f], nrm[f])))
cat = pd.DataFrame(cat)
cat.to_csv('attack_category_summary.csv', index=False)
pv = cat.pivot_table(index=['attack_cat', 'feature'], columns='partition', values='cliffs_delta_vs_normal')
pv['same_sign'] = np.sign(pv.train) == np.sign(pv.test)
pv.to_csv('attack_category_consistency.csv')
mix = pd.concat({p: d.attack_cat.value_counts(normalize=True) for p, d in parts.items()}, axis=1)
mix.to_csv('class_mix.csv')
out['label_counts'] = {p: d.label.value_counts().to_dict() for p, d in parts.items()}
out['cat_sign_agreement_frac'] = float(pv.same_sign.mean())
json.dump(out, open('environment_and_counts.json', 'w'), indent=1, default=str)

# Figures (log1p scale because of heavy right skew)
fig, ax = plt.subplots(2, 5, figsize=(22, 8))
for i, p in enumerate(parts):
    d = parts[p]
    for j, f in enumerate(F):
        data = [np.log10(d.loc[d.label == l, f] + 1e-6 if f == 'dur' else d.loc[d.label == l, f] + 1) for l in (0, 1)]
        ax[i, j].boxplot(data, labels=['normal', 'malicious'], showfliers=False)
        ax[i, j].set_title(f'{p}: log10({f}{"+1e-6" if f=="dur" else "+1"})')
plt.tight_layout(); plt.savefig('fig_boxplots.png', dpi=110)

fig, ax = plt.subplots(1, 1, figsize=(7, 4))
x = np.arange(len(F))
ax.bar(x - .2, [c['delta_train'] for c in cons], .4, label='train')
ax.bar(x + .2, [c['delta_test'] for c in cons], .4, label='test')
ax.set_xticks(x); ax.set_xticklabels(F); ax.axhline(0, c='k'); ax.legend()
ax.set_ylabel("Cliff's delta (malicious vs normal)")
plt.tight_layout(); plt.savefig('fig_effect_sizes.png', dpi=110)

pd.set_option('display.width', 250); pd.set_option('display.max_columns', 50)
print(res.drop(columns=['n_normal', 'n_mal']).round(4).to_string())
print(pd.DataFrame(cons).round(3).to_string())
print(pv.round(2).to_string()); print('sign agreement', out['cat_sign_agreement_frac'])
print(mix.round(3).to_string())
