#!/usr/bin/env python3
import sys
import os
import json
import subprocess
import re


_RGX_CDB = re.compile(r'Building compilation database (?P<path>.+?/compile_commands.json)')


def main():
    print('Running pio run -t compiledb...')
    build_p = subprocess.Popen('pio run -t compiledb'.split(), stdout=subprocess.PIPE, universal_newlines=True)
    cdb_path = None
    for line in build_p.stdout:
        for m in _RGX_CDB.finditer(line):
            cdb_path = m.group('path')
        if cdb_path is not None:
            break
    if (return_code := build_p.wait(30.)) != 0:
        print(f'Failed with exit code {return_code}.')
        sys.exit(return_code)

    print('Filtering compiledb entries...')
    with open(cdb_path, 'r') as fp:
        cdb = json.load(fp)

    pio_dir = os.path.join(os.getcwd(), '.pio').lower()
    proj_dir = os.getcwd().lower()

    def _filter_entry(entry):
        file = entry.get('file', '').lower()
        return file.startswith(proj_dir) and not file.startswith(pio_dir)

    cdb = list(filter(_filter_entry, cdb))
    cdb_path = 'compile_commands.json'

    print('Overwriting compile_commands.json (a backup will be made)...')
    if os.path.isfile(cdb_path):
        os.rename(cdb_path, f'{cdb_path}.bak')

    with open(cdb_path, 'w') as fp:
        json.dump(cdb, fp, indent=4)


if __name__ == '__main__':
    main()
