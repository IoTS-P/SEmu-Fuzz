# Quick Start

## 1 Preparing the testcase configuration file

Note: Incorrect configurations will lead to unexpected behaviors of SEmu like low fuzzing block coverage or inaccurate simulation.

### Our fuzz tests
You can use the configuration files provided in our [fuzz_tests](https://github.com/MCUSec/SEmu/tree/main/DataSet/fuzz_tests).

1. If you have cloned [SEmu](https://github.com/MCUSec/SEmu), just cd `/pathto/SEmu/DataSet/fuzz_tests`.

2. If not, clone it and cd DataSet:

    ```bash
    git clone https://github.com/MCUSec/SEmu
    cd SEmu/DataSet/fuzz_tests
    ```

    And use `semu-fuzz-helper` to generate all the configs:
    ```bash
    semu-fuzz-helper config base_configs.yml
    ```

3. You can run this command to see all the configuration files:
    ```bash
    find . -maxdepth 3 -type f -name "*config*"
    ```

    You will see one `base_configs.yml` and many `semu_config.yml`.

Now you can turn to [next phrase](#2-use-semu-fuzz).

### Your own testcases

If you want to test your own firmware, please refer to this [intruction](./configuration.md) and [our paper](https://doi.org/10.1145/3548606.3559386) to edit the user configuration file.

When you finish it, you will get one `base_configs.yml` and many `semu_config.yml`.

Then you can turn to [next phrase](#2-use-semu-fuzz).

## 2 Use SEmu-Fuzz

### Run a single testcase

As mentioned above, `semu_config.yml` is prepared in [Phrase 1](#1-preparing-the-testcase-configuration-file).

When running AFL, the `input_file` is provided by AFL, but when not using AFL, you can provide any file of your choice.

1. Run without AFL: 

    ```bash
    semu-fuzz <pathto/input_file> <pathto/semu_config.yml>
    ```
    Note: If you meet "Core dump" when run a single test, use `pip freeze` to determine your dependency.

2. Run with AFl:

    ```bash
    afl-fuzz -U -m none -i fuzz_tests/f429/CNC/base_inputs -o fuzz_tests/f429/CNC/output2 -t 10000 -- semu-fuzz @@ fuzz_tests/f429/CNC/semu_config.yml
    ```

    Note: If you don't have `afl-fuzz`, please refer to [../](../install_local.sh#L29-L41) to install.


### Run batch testcases

Recommend running by our `semu-fuzz-helper`.

Run:

```bash
cd /pathto/testcase_path
semu-fuzz-helper run base_configs.yml
```

> You can use `-t` to limit the time to run, `-t 24` means run 24h test.

Note: If you meet error when run it, you can refer to the last part [Run a single testcase](#run-a-single-testcase), run testcases one by one to find out.

## 3 Draw BB coverage images

Recommend stating by our `semu-fuzz-helper`.

Run:

```bash
cd /pathto/testcase_path
semu-fuzz-helper run base_configs.yml
```

> You can use `-t` to set the xrange of images, `-t 24` means xrange is 24h.

Note: Please don't change the code in semu-fuzz when stating.

## More

1. [configuration.md](docs/configuration.md): This document describes the composition of **the configuration file for testcases** and how to **generate batch configuration files**.
2. [debug_in_vscode.md](docs/debug_in_vscode.md): This documentation explains how to **debug in vscode** and how to **generate batch vscode launch files of testcases**.
