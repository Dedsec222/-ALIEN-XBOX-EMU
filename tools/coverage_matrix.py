#!/usr/bin/env python3
"""Join executed synthetic instruction encodings to a linear AT&T disassembly inventory."""
import argparse
import collections
import csv
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT

parser=argparse.ArgumentParser()
parser.add_argument('static_report',type=Path)
parser.add_argument('trace_directory',type=Path)
parser.add_argument('output',type=Path)
args=parser.parse_args()
engine=Cs(CS_ARCH_X86,CS_MODE_64)
engine.syntax=CS_OPT_SYNTAX_ATT
observed=collections.defaultdict(set)
for path in args.trace_directory.glob('*.txt'):
    for line in path.read_text().splitlines():
        if not line.startswith('bytes='): continue
        insn=next(engine.disasm(bytes.fromhex(line[6:]),0,count=1),None)
        if insn: observed[insn.mnemonic].add(insn.bytes.hex())
with args.output.open('w') as out:
    writer=csv.writer(out)
    writer.writerow(['static_mnemonic','linear_records','distinct_tested_encodings','sample_tested_bytes'])
    for name,count in json.loads(args.static_report.read_text())['mnemonics'].items():
        examples=sorted(observed[name])
        writer.writerow([name,count,len(examples),' '.join(examples[:4])])
