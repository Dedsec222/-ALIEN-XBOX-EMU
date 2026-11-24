#!/usr/bin/env python3
"""Summarize existing ALIEN_INSN_TRACE output without executing a guest."""
import collections, re, sys
if len(sys.argv)!=2: sys.exit('usage: alien_coverage.py TRACE_LOG')
counts=collections.Counter(); depths=collections.Counter(); stops=[]; blocks=collections.Counter(); retired=0
with open(sys.argv[1],errors='replace') as f:
    for line in f:
        m=re.search(r'INSN depth=(\d+) step=\d+ rip=([0-9a-fA-F]+)',line)
        if m:
            counts[int(m[2],16)]+=1; depths[int(m[1])]+=1
        elif m:=re.search(r'BLOCK depth=(\d+) first=([a-fA-F0-9]+) last=([a-fA-F0-9]+) retired=(\d+)',line):
            blocks[(int(m[1]),int(m[2],16),int(m[3],16))]+=1
            retired+=int(m[4])
        elif line.startswith(('Stop RIP:', 'Stop bytes:', 'Execution exit:', 'Imports resolved:', 'Instructions:')): stops.append(line.strip())
print('Trace attempts:',sum(counts.values()))
print('Unique attempted RIPs:',len(counts))
print('Attempts by callback depth:',dict(sorted(depths.items())))
print('Most visited RIPs:')
for rip,n in counts.most_common(15): print(f'  {rip:#x}: {n}')
for line in stops: print(line)
if blocks:
    print('Executed block runs:',sum(blocks.values()),'distinct block ranges by depth:',len(blocks),'retired instructions:',retired)
    for (depth,first,last),hits in blocks.most_common(15): print(f'  depth={depth} {first:#x}..{last:#x}: {hits}')
if not counts and not blocks: print('No instruction trace found; enable ALIEN_INSN_TRACE=1 for bounded tests.')
