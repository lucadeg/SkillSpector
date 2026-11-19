import collections, datetime, hashlib, json, os, pathlib, subprocess, sys, concurrent.futures
base=pathlib.Path.home()/'.hermes'
repo=base/'MVX-founder-OS'
scanner=base/'SkillSpector'
exe=scanner/'.venv/Scripts/skillspector.exe'
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
out=scanner/'audits'/('FounderOS-'+stamp)
out.mkdir(parents=True)
def git(root,*args):
    return subprocess.check_output(['git','-C',str(root),*args],text=True,encoding='utf-8',errors='replace').strip()
skip={'.git','node_modules','.venv','venv','target','dist','build','.next','.turbo','__pycache__','.cache','coverage'}
manifests={}
walk_errors=[]
for root,dirs,files in os.walk(repo,followlinks=False,onerror=lambda e:walk_errors.append(str(e))):
    dirs[:]=[d for d in dirs if d.lower() not in skip and not pathlib.Path(root,d).is_symlink() and not getattr(pathlib.Path(root,d),'is_junction',lambda:False)()]
    for f in files:
        if f.lower()=='skill.md':
            p=pathlib.Path(root,f)
            if not p.is_symlink(): manifests[p.relative_to(repo).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
tracked=[f for f in git(repo,'ls-files').splitlines() if pathlib.PurePosixPath(f).name.lower()=='skill.md']
inventory={'host':os.environ.get('COMPUTERNAME'),'repo':str(repo),'commit':git(repo,'rev-parse','HEAD'),'scanner_commit':git(scanner,'rev-parse','HEAD'),'manifests':manifests,'tracked_missing':sorted(set(tracked)-set(manifests)),'excluded_directory_names':sorted(skip),'walk_errors':walk_errors,'llm':False}
(out/'inventory.json').write_text(json.dumps(inventory,indent=2),encoding='utf-8')
print('INVENTORY',len(manifests),'tracked',len(tracked),'missing',len(inventory['tracked_missing']),'errors',len(walk_errors),'dir',out,flush=True)
groups=collections.defaultdict(list)
for name in manifests: groups[str((repo/name).parent.parent)].append(name)
jobs=[]
for parent,names in groups.items():
    # Single-skill scan for each manifest if the parent is a skill too or only one member.
    if len(names)==1 or any(p.lower().startswith(pathlib.Path(parent).relative_to(repo).as_posix().lower()+'/skill.md') for p in manifests):
        jobs.extend((str((repo/n).parent),[n],False) for n in names)
    else: jobs.append((parent,names,True))
def scan(job):
    path,names,recursive=job
    key=hashlib.sha256(path.encode()).hexdigest()[:16]
    cmd=[str(exe),'scan',path,'--no-llm','--format','json','--fail-on-incomplete','--fail-on-findings']
    if recursive: cmd+=['--recursive','--max-skills',str(len(names))]
    try:
        proc=subprocess.run(cmd,cwd=scanner,capture_output=True,timeout=1200)
        (out/(key+'.json')).write_bytes(proc.stdout)
        (out/(key+'.stderr.log')).write_bytes(proc.stderr)
        try: data=json.loads(proc.stdout); valid=True
        except Exception: data={}; valid=False
        result={'path':path,'expected':names,'recursive':recursive,'exit_code':proc.returncode,'valid_json':valid,'report':key+'.json','top_keys':list(data) if isinstance(data,dict) else [],'risk':data.get('risk_assessment') if isinstance(data,dict) else None,'issues':len(data.get('issues',[])) if isinstance(data,dict) and isinstance(data.get('issues',[]),list) else None}
    except Exception as e: result={'path':path,'expected':names,'error':str(e)}
    print('GROUP',json.dumps(result,ensure_ascii=True),flush=True)
    return result
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
    results=list(pool.map(scan,jobs))
summary={'inventory_count':len(manifests),'groups':results,'report_dir':str(out)}
(out/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
print('FINISHED',json.dumps({'inventory_count':len(manifests),'groups':len(results),'valid_reports':sum(r.get('valid_json',False) for r in results),'report_dir':str(out)}),flush=True)
