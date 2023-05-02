'''
Description: Draw bb img with stat_output in ./plots dir.
Usage: Just used in stat_bb_coverage.py
'''

import subprocess
import os
import sys

plots_dir = 'plots'
samples_dir = 'samples'
fuzzs_block_dir = 'stat_output/new_blocks.txt'

import datetime

def draw(elf_dir, duration):
    print('[*] Plot Block Coverage of %s...' % elf_dir, end="\t")

    # create plots dir
    if not os.path.exists(plots_dir):
        os.mkdir(plots_dir)

    # dirname
    fuzz_block_path = os.path.join(elf_dir, fuzzs_block_dir)
    plot_path = os.path.join(plots_dir, "plot-" + elf_dir.replace("/", "-"))
    plot_png_path = plot_path + ".png"
    plot_dat_path = plot_path + ".dat"

    # read data
    data = []
    with open(fuzz_block_path, 'r') as f:
        for line in f:
            timestamp, value = line.strip().split('\t')[:2]
            data.append((int(timestamp), int(value)))

    time_format = '%d/%H:%M'

    # translate timestamp
    start_timestamp = data[0][0]
    dates = []
    for timestamp, _ in data:
        date = datetime.datetime.fromtimestamp(timestamp - start_timestamp).strftime(time_format)
        dates.append(date)

    # write to dat file
    with open(plot_dat_path, 'w') as f:
        for i in range(len(data)):
            f.write('{} {}\n'.format(dates[i], data[i][1]))

    xrange_end = (datetime.datetime.fromtimestamp(data[0][0] - start_timestamp) + datetime.timedelta(seconds=duration)).strftime(time_format)

    # set xtics 4 hour starting from 0
    duration_hours = duration / 3600

    # draw by gnuplot
    gnuplot_code = 'set term png;'
    gnuplot_code += f'set output "{plot_png_path}";'
    gnuplot_code += 'set xdata time;'
    gnuplot_code += f'set timefmt "{time_format}";'
    gnuplot_code += f'set format x "{time_format}";'
    gnuplot_code += 'set xlabel "Time";'
    gnuplot_code += 'set ylabel "BBs";'
    gnuplot_code += f'set title "{elf_dir}";'
    gnuplot_code += 'set xrange ["{}":"{}"];'.format(dates[0], xrange_end)
    gnuplot_code += 'set xtics 14400;'

    gnuplot_code += f'plot "{plot_dat_path}" using 1:2 with lines notitle ;'

    try:
        output = subprocess.check_output(["gnuplot", "-e", gnuplot_code])
    except subprocess.CalledProcessError as e:
        print(f"[-] Gnuplot Error!")
        print(gnuplot_code)
    else:
        print(f"[+] Output coverage plot png to {plot_png_path}")
