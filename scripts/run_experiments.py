#!/usr/bin/env python3
from pathlib import Path
import argparse, sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from continuity.experiment import run_main, run_ablation, run_performance
p=argparse.ArgumentParser(); p.add_argument('--output', default=str(ROOT/'results')); p.add_argument('--quick', action='store_true'); a=p.parse_args()
_, summary=run_main(a.output,a.quick); print(summary.to_string(index=False))
print('\nAblation:'); print(run_ablation(a.output,a.quick).to_string(index=False))
print('\nPerformance:'); perf, scale=run_performance(a.output,100 if a.quick else 400); print(perf.to_string(index=False)); print(scale.to_string(index=False))
