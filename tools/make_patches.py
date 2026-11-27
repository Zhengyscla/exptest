import urllib.request, difflib, os

base = 'https://raw.githubusercontent.com/LSPosed/LSPrivilege/main/'
repo = r'work\LSPrivilege_src\LSPrivilege-main'
out = r'oxf-an00-20261127\patches'
os.makedirs(out, exist_ok=True)

files = ['src/core/attack/ops.hpp', 'src/core/session/backend/cve_2026_43499_backend.cpp']
for rel in files:
    try:
        up = urllib.request.urlopen(base + rel, timeout=30).read().decode('utf-8').splitlines()
    except Exception as e:
        print('fetch fail', rel, e)
        continue
    local = open(os.path.join(repo, rel.replace('/', os.sep)), encoding='utf-8').read().splitlines()
    diff = list(difflib.unified_diff(up, local, fromfile='a/' + rel, tofile='b/' + rel, lineterm=''))
    name = os.path.basename(rel) + '.patch'
    with open(os.path.join(out, name), 'w', encoding='utf-8') as f:
        f.write('\n'.join(diff) + '\n')
    print(name, 'hunks lines:', len(diff))
