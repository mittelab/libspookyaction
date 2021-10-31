import git, json, sys

repo=git.Repo()
tag = next((tag for tag in repo.tags if tag.commit == repo.head.commit), None)

with open('library.json') as lib_file:
    version = json.load(lib_file).get("version", None)
    
    if not version:
        sys.exit(f"YOU DINGUS!\nyou have forgotten the version in the library.json file")
    if not tag:
        sys.exit(f"WHAT are you doing, step-commit?\nNO tag associated with commit {repo.head.commit}")
    if str(version) != str(tag):
        sys.exit(f"git tag[{tag}] is not the same as in the library.json[{version}]")
