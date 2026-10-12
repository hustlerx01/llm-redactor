"""python -m redactor.evaluate -> per-type precision/recall + latency."""
import json, pathlib, statistics, time
from collections import defaultdict
from .detectors import find

def main():
    rows = [json.loads(l) for l in (pathlib.Path(__file__).resolve().parent.parent / "data/eval.jsonl").read_text().splitlines()]
    tp, fp, fn = defaultdict(int), defaultdict(int), defaultdict(int); fps, fns, lat = [], [], []
    for r in rows:
        t0 = time.perf_counter(); spans = find(r["text"]); lat.append((time.perf_counter() - t0) * 1e6)
        got = {(k, r["text"][s:e]) for s, e, k in spans}; want = {(e["type"], e["value"]) for e in r["entities"]}
        for x in got & want: tp[x[0]] += 1
        for x in got - want: fp[x[0]] += 1; fps.append({"text": r["text"], "pred": x})
        for x in want - got: fn[x[0]] += 1; fns.append({"text": r["text"], "missed": x})
    types = sorted(set(tp) | set(fp) | set(fn)); table = {}
    for k in types + ["ALL"]:
        a, b, c = (sum(d.values()) for d in (tp, fp, fn)) if k == "ALL" else (tp[k], fp[k], fn[k])
        table[k] = {"tp": a, "fp": b, "fn": c, "precision": round(a / (a + b), 3) if a + b else 0, "recall": round(a / (a + c), 3) if a + c else 0}
    res = {"n_rows": len(rows), "per_type": table, "false_positives": fps, "false_negatives": fns,
           "latency_us": {"median": round(statistics.median(lat), 1), "p95": round(sorted(lat)[int(len(lat) * .95)], 1)}}
    for k, v in table.items(): print(f"{k:13} P={v['precision']:.3f} R={v['recall']:.3f} tp={v['tp']} fp={v['fp']} fn={v['fn']}")
    print("latency_us", res["latency_us"]); print("FP:", fps); print("FN:", fns)
    pathlib.Path("results").mkdir(exist_ok=True); pathlib.Path("results/eval.json").write_text(json.dumps(res, indent=2, ensure_ascii=False))
    return res

if __name__ == "__main__":
    main()
