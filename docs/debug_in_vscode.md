# Debug in VScode

## Introduction

Please refer to [Python debugging in VS Code](https://code.visualstudio.com/docs/python/debugging).

## Generate batch vscode launch files

Recommend using `semu-fuzz-helper`.

Firstly, preparing the testcase configuration file refer to [./configuration.md](./configuration.md).

Run:
```bash
semu-fuzz-helper launch base_configs.yml
```

> use `-a` to dump launch with afl.

Note: This helper will dump the absolute path, so you don't have to worry about the workspace folder of VScode.


