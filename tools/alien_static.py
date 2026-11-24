#!/usr/bin/env python3
"""Read-only PE executable-section audit using LLVM objdump or GNU objdump."""
import argparse, collections, json, re, shutil, struct, subprocess
from pathlib import Path

def sections(path):
    with open(path,'rb') as f:
        if f.read(2)!=b'MZ': raise ValueError('Not an MZ file')
        f.seek(60); off=struct.unpack('<I',f.read(4))[0]; f.seek(off)
        if f.read(4)!=b'PE\0\0': raise ValueError('Not a PE file')
        machine,n,_,_,_,opt,_=struct.unpack('<HHIIIHH',f.read(20))
        if machine!=0x8664: raise ValueError('Not x86-64 PE')
        f.seek(opt,1); result=[]
        for _ in range(n):
            h=f.read(40); name=h[:8].split(b'\0')[0].decode('ascii','replace')
            vs,rva,raw,ptr=struct.unpack_from('<IIII',h,8); flags=struct.unpack_from('<I',h,36)[0]
            if flags&0x20000000 and raw: result.append(dict(name=name,virtual_size=vs,raw_size=raw,rva=rva))
        return result

def scan(path,tool):
    sec=sections(path); counts=collections.Counter(); skipped=0; decoded=0
    cmd=[tool,'-d','--no-show-raw-insn']
    for s in sec: cmd+=['-j',s['name']]
    if not sec: raise ValueError('No executable sections')
    p=subprocess.Popen(cmd+[str(path)],stdout=subprocess.PIPE,text=True,errors='replace')
    pattern=re.compile(r'^\s*[0-9a-fA-F]+:\s+([^\s]+)')
    for line in p.stdout:
        m=pattern.match(line)
        if not m: continue
        op=m[1].lower()
        if op.startswith('.') or op in ('(bad)','<unknown>','unknown'): skipped+=1; continue
        counts[op]+=1; decoded+=1
    if p.wait(): raise RuntimeError('Disassembler failed; no complete report')
    return dict(file_size=path.stat().st_size,sections=sec,executable_raw_bytes=sum(s['raw_size'] for s in sec),linear_decoded_instructions=decoded,unknown_records=skipped,unique_mnemonics=len(counts),mnemonics=dict(counts.most_common()),warning='Linear disassembly may include data/padding or miss code; not boot progress or interpreter support coverage.')

def main():
    p=argparse.ArgumentParser(); p.add_argument('exe',type=Path); p.add_argument('--output',type=Path,default=Path('alien-static.json')); p.add_argument('--tool'); a=p.parse_args()
    tool=a.tool or shutil.which('llvm-objdump') or shutil.which('objdump')
    if not tool: p.error('Install llvm or binutils')
    r=scan(a.exe,tool); a.output.write_text(json.dumps(r,indent=2)); print('Executable bytes:',r['executable_raw_bytes']); print('Linear decoded instructions:',r['linear_decoded_instructions']); print('Unknown records:',r['unknown_records']); print('Unique mnemonics:',r['unique_mnemonics']); print('Top 25:',list(r['mnemonics'].items())[:25]); print(r['warning']); print('Report:',a.output)
if __name__=='__main__': main()
