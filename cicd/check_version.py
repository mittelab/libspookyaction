#!/usr/bin/env python3
import git
import json
import sys


def main(args):
    repo = git.Repo()
    tag = next((tag for tag in repo.tags if tag.commit == repo.head.commit), None)

    with open(args.library_json) as lib_file:
        version = json.load(lib_file).get('version', None)
        if not version:
            sys.exit(f'YOU DINGUS!\nyou have forgotten the version in the library.json file')
        if not tag:
            sys.exit(f'WHAT are you doing, step-commit?\nNO tag associated with commit {repo.head.commit}')
        if str(version) != str(tag):
            sys.exit(f'git tag[{tag}] is not the same as in the library.json[{version}]')


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser('Ensures that the git tag matches the library version.')
    parser.add_argument('library_json', help='File library.json to test')
    main(parser.parse_args())
