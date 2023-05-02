# Configuration

## 1 Simplest configuration (Recommend)


When your testcase is elf or axf, whose arch is ARMCortexM, you can simply use `semu-fuzz-helper` to dump the whole configuration.

If your testcase is special, `semu-fuzz-helper` can also dump the basic yml for you.

### 1.1 Make dir for your testcase

We recommend creating a separate folder for each test firmware to store its configuration files and output files. 

Assuming you have three firmware files named `a1`, `a2`, and `a3`, and you need to test all of them at once under the name `test1`, your file structure should look like this:

```bash
test1
├── base_configs.yml
├── a1
│   └── a1.elf
├── a2
│   └── a2.elf
└── a3
    └── a3.elf
```

### 1.2 Set base configs

If you want to run `semu-fuzz` in path `test1/`, you should set base_configs.yml:

```yml
a1/a1.elf:
  rules: '/pathto/rules/xx.txt' # relative or absolute path to semu rule
  fork_points:
  - 0x0 # the start point of the main loop
a2/a2.elf:
  rules: '/pathto/rules/xx.txt' # relative or absolute path to semu rule
  fork_points:
  - 0x0 # the start point of the main loop
```

If you want to run it in other path, like the parent of `test1`, please change `a1/a1.elf` to `test1/a1/a1.elf`.

Note: Only `rules` are required configurations, and other configurations can be automatically generated or set by default. For detailed explanations of all the configurations, please refer to the code file [../semu_fuzz/configuration/config.py](../semu_fuzz/configuration/config.py) or the next section [Whole configuration](#2-whole-configuration).

But we recommend setting `fork_points` to exit the loop in a timely manner during emulation or fuzz testing.

### 1.3 Generate all the configs

Run:
```bash
semu-fuzz-helper config base_configs.yml
```

Then you will get `semu_config.yml` next to each test firmware.

## 2 Whole configuration

When your testcase is bin or not ARM, `semu-fuzz-helper` will fail to dump the whole configuration. Then this section will help you fill the blank.

All configuration items and their default values are as follows:

```python
default_config = Namespace(
    memory_map=None,  # memory map
    entry_point=None,  # entry point
    initial_sp=None,  # initial stack pointer
    rules=None,  # rule path
    symbols=None,  # symbol table
    isr_vector=0, # the isr vector (no use now)
    emulate_mode='fuzz',  # support: emulate, fuzz
    begin_point=0,  # the beginning of the data input, default is entry_point
    fork_points=[],  # the point of the main loop of the bin
    fork_point_times=2, # the max time to meet fork point when fuzz
    enable_native=True, # True if your want to use c 
    enable_bitband=True,  # note: bitband used only when Cortex M3 and M4, so if not, set it False
    enable_systick=True,
    systick_reload=globs.INTERRUPT_INTERVAL  # the block interval of systick, default is 1500
)
```

The default configuration is a set of options that can be used to configure the behavior of the emulator.

### Required

The required configuration items are `memory_map`, `entry_point`, `initial_sp`, and `rules`. The `memory_map` option is architecture-dependent and is used to configure memory mappings and set the read-write permissions for each region. The `entry_point` option specifies the entry point of the binary, while the `initial_sp` option specifies the initial stack pointer. The `rules` option specifies the path to the rule file.

1. The configuration format of `memory_map` is shown as follows, and it must be configured with the flash field to store the executable test program. Other memory map configurations can refer to the [memory configuration file for Cortex-M architecture](../semu_fuzz/helper/configs/hw/cortexm_memory.yml).

    ```yml
    memory_map:
      flash:
        base_addr: 0x8000000
        file: CNC.bin
        permissions: r-x
        size: 0x2000000
    ```

2. `entry_point`, `initial_sp` can often be obtained through IDA.

3. `rules` is the rule text corresponding to the MCU you are using, which is extracted by SEmu's natural language model.

### optional

1. `fork_points` and `fork_point_times`: `fork_points` are points set by user. During fuzz testing, if the number of passes through this point exceeds `fork_point_times`, the program will exit. This point is usually set to the starting point of the main execution flow of the program loop, and `fork_point_times` is usually set to 2 so that the main program flow will exit after one execution. If not set, the program can only end when the data channel is read empty, and for some test cases, the data channel may never be read empty and may never end.

    Note: Many `fork_points` can be set, and `fork_point` can also be a dead loop point that is not reached, which can also avoid getting stuck in an unavoidable dead loop or waiting for a function to execute for an extended period during fuzz testing.

2. `begin_point` is a point that users can set, and it is the initial placement point of the input data. If not set, it will be assigned to `entry_point` in the program.

3. `emulate_mode` is the current simulation mode. If fuzz is selected, the `unicornafl` simulation program will be called, and afl can be connected for fuzz testing. If emulate is selected, the original `unicorn.emu_start` will be called, and it cannot connect to afl for fuzz testing.

4. `enable_native` determines whether to enable the native module, which is a module rewritten in C for acceleration. Currently, only the nvic native module is provided.

    Note: If unicorn is not installed locally and there is no libunicorn, an error will occur after `enable_native`. You can refer to [install_local.sh#L38-L39](../install_local.sh#L38-L39)

5. `symbols`: This configuration item is the content of the symbol table. You only need to import the symbol table file in the `semu_config.yml` to configure it. If not configured, it only affects the output of function debugging information during debugging and does not affect fuzz testing and emulation.

6. `enable_bitband`: When set to `True`, it enables the bit-band feature, which is only available on Cortex M3 and M4 processors. If your processor does not support this feature, you should set this to `False`.

7. `enable_systick`: This configuration item enables the SysTick timer interrupt, which is commonly used for timing purposes in embedded systems. Setting this to `True` will enable the SysTick timer, while setting it to `False` will disable it.

8. `systick_reload`: This configuration item sets the block interval of the SysTick timer. The default value is `1500`. This value determines how often the SysTick timer interrupt will be triggered. For example, if you set this value to 1000, the SysTick timer will generate an interrupt every 1000 ticks.

## 3 Some Configuration when stat and debug

### BB coverage stat

When stating BB coverage, `valid_basic_blocks.txt` is needed for every testcase.

You can use [../ida_helper/ida_dump_valid_blocks.py](../ida_helper/ida_dump_valid_blocks.py).

Usage: In IDA, click File-Script file..., choose this script.

### Function debug

When needing function debug output, `syms.yml` is needed.

You can dump it with `semu-fuzz-helper config base_configs.yml -s`(not recommend), or use [../ida_helper/ida_dump_symbols.py](../ida_helper/ida_dump_symbols.py).

Usage: In IDA, click File-Script file..., choose this script.