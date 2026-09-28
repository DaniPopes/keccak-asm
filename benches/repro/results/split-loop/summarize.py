import csv,statistics as st
from pathlib import Path
root=Path(__file__).parent
sizes=[0,20,32,64,135,136,137,272,532,1024,4096,16384,131072]
report=['# x86 split-loop comparison','', 'Ryzen 9 7950X, CPU 12, Rust 1.100.0-nightly (feaadeeac), release LTO. Same tracked benches/repro matrix and default features. Before is ab421ae; after applies the same full-block/tail split to AVX2 and AVX-512. Values are medians of five samples in cycles/hash. Negative change is better.','']
for backend in ['avx2','native']:
 paths=[root/f'{v}-{backend}.tsv' for v in ['before','after']]
 if not all(p.exists() for p in paths):continue
 groups=[]
 for p in paths:
  rows=list(csv.DictReader(p.open(),delimiter='\t'))
  assert len(rows)==806,(p,len(rows))
  assert all(r['enabled']==r['running'] for r in rows)
  d={}
  for r in rows:
   if r['implementation']=='shared':d.setdefault((int(r['bytes']),r['shape'],r['mode']),[]).append(int(r['cycles'])/int(r['iterations']))
  assert all(len(g)==5 for g in d.values())
  groups.append(d)
 report += [f'## {backend}','','| Bytes | Runtime before | Runtime after | Change | Fixed change | Latency change (runtime) |','|---:|---:|---:|---:|---:|---:|']
 for n in sizes:
  a,b=[st.median(d[n,'runtime','throughput']) for d in groups]
  f,g=[st.median(d[n,'fixed','throughput']) for d in groups]
  l,m=[st.median(d[n,'runtime','latency']) for d in groups]
  report.append(f'| {n} | {a:.1f} | {b:.1f} | {100*(b/a-1):+.2f}% | {100*(g/f-1):+.2f}% | {100*(m/l-1):+.2f}% |')
 report+=['']
(root/'generated-comparison.md').write_text('\n'.join(report)+'\n')
print('\n'.join(report))
