import csv,statistics as s
from pathlib import Path
root=Path(__file__).parent
out=['| Backend | Bytes | Current cycles | Stack cycles | Assembly cycles | vs assembly | vs stack |','|---|---:|---:|---:|---:|---:|---:|']
for backend in ['native','avx2']:
 groups={}
 for r in csv.DictReader((root/f'{backend}.tsv').open(),delimiter='\t'):
  assert r['enabled']==r['running']
  if r['shape']=='runtime' and r['mode']=='throughput':groups.setdefault((int(r['bytes']),r['implementation']),[]).append(int(r['cycles'])/int(r['iterations']))
 for n in [0,20,32,64,135,136,137,272,532,1024,4096,16384,131072]:
  v=[]
  for impl in ['shared','stack','asm']:
   g=groups[n,impl];assert len(g)==5;v.append(s.median(g))
  a,b,c=v;out.append(f'| {backend} | {n} | {a:.1f} | {b:.1f} | {c:.1f} | {(a/c-1)*100:+.1f}% | {(a/b-1)*100:+.1f}% |')
(root/'comparison.md').write_text('\n'.join(out)+'\n')
print('\n'.join(out))
