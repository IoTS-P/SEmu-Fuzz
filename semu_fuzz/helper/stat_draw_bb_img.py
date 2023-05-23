'''
Description: Draw bb img with stat_output in ./plots dir.
Usage: Just used in stat_bb_coverage.py
'''

import subprocess
import os

plots_dir = 'plots'

import datetime

def draw(stat_path, num, duration):
    elf_dir = os.path.dirname(stat_path)
    print('[*] Plot Block Coverage of %s...' % elf_dir, end="\t")

    # create plots dir
    if not os.path.exists(plots_dir):
        os.mkdir(plots_dir)

    # output path
    plot_png_path = os.path.join(plots_dir, "plot-%s" % (elf_dir.replace("/", "-"))) + '.png'

    # init gnuplot code
    time_format = '%d/%H:%M'
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
    gnuplot_code += 'set key right bottom;'

    # get data and record as dat file
    for i in range(num):
        fuzzs_block_dir = os.path.join(stat_path, str(i))
        fuzz_block_path = os.path.join(fuzzs_block_dir, "new_blocks.txt")
        plot_dat_path = os.path.join(plots_dir, "%d-plot-%s" % (i, elf_dir.replace("/", "-"))) + '.dat'

        # read data
        data = []
        with open(fuzz_block_path, 'r') as f:
            for line in f:
                timestamp, value = line.strip().split('\t')[:2]
                data.append((int(timestamp), int(value)))

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
        
        # draw by gnuplot
        gnuplot_code += f'plot "{plot_dat_path}" using 1:2 with lines TEST{i}, \\'

    try:
        output = subprocess.check_output(["gnuplot", "-e", gnuplot_code])
    except subprocess.CalledProcessError as e:
        print(f"[-] Gnuplot Error!")
        print(gnuplot_code)
    else:
        print(f"[+] Output coverage plot png to {plot_png_path}")
