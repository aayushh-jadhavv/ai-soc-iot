"""Binary metrics with fixed labels, tied-score AP and explicit missing support."""

import numpy as np


def binary_metrics(labels, scores):
    y, s = np.asarray(labels), np.asarray(scores, dtype=np.float64)
    if y.ndim != 1 or s.shape != y.shape or not len(y):
        raise ValueError("Nonempty aligned labels and scores required")
    if not np.isin(y, [0, 1]).all() or not np.isfinite(s).all() or ((s < 0) | (s > 1)).any():
        raise ValueError("Invalid labels or probabilities")
    pred = s >= 0.5
    tp, tn = int(np.sum(pred & (y == 1))), int(np.sum(~pred & (y == 0)))
    fp, fn = int(np.sum(pred & (y == 0))), int(np.sum(~pred & (y == 1)))
    def ratio(a, b):
        return a / b if b else None
    attack_f1 = ratio(2 * tp, 2 * tp + fp + fn)
    benign_f1 = ratio(2 * tn, 2 * tn + fp + fn)
    # No checkpoint selection on a one-class development set.
    macro = (attack_f1 + benign_f1) / 2 if tp + fn and tn + fp else None
    ap = None
    if tp + fn:
        order = np.argsort(-s, kind="stable")
        sy, ss = y[order], s[order]
        ends = np.r_[np.flatnonzero(ss[:-1] != ss[1:]), len(y) - 1]
        cum = np.cumsum(sy)[ends]
        recalls, precisions = cum / (tp + fn), cum / (ends + 1)
        ap = float(np.sum(np.diff(np.r_[0.0, recalls]) * precisions))
    return dict(sample_count=len(y), attack_count=tp + fn, benign_count=tn + fp,
                attack_prevalence=(tp + fn) / len(y), threshold=0.5,
                tn=tn, fp=fp, fn=fn, tp=tp, precision=ratio(tp, tp + fp),
                recall=ratio(tp, tp + fn), false_positive_rate=ratio(fp, tn + fp),
                attack_f1=attack_f1, benign_f1=benign_f1, macro_f1=macro,
                pr_auc=ap, pr_auc_method="noninterpolated_average_precision_ties_grouped")


def development_metrics(rows, scores):
    y = np.array([r["label"] for r in rows])
    scores = np.asarray(scores)
    result = binary_metrics(y, scores)
    families = {}
    for family in sorted({"benign", "reconnaissance", "dos"} | {r["family"] for r in rows}):
        mask = np.array([r["family"] == family for r in rows])
        support = int(mask.sum())
        # These are binary involvement/detection metrics, never family predictions.
        families[family] = dict(support=support,
            independent_source_groups=len({r["group_id"] for r, keep in zip(rows, mask) if keep}),
            detected=int(np.sum(scores[mask] >= .5)) if support else None,
            detection_rate=float(np.mean(scores[mask] >= .5)) if support else None,
            binary_vs_benign=(binary_metrics(y[mask | (y == 0)], scores[mask | (y == 0)])
                              if family != "benign" and support else None))
    result["per_family"] = families
    result["per_group"] = {}
    for group in sorted({r["group_id"] for r in rows}):
        mask = np.array([r["group_id"] == group for r in rows])
        result["per_group"][group] = binary_metrics(y[mask], scores[mask])
    return result
