'''
Description: Draw bb img with stat_output in ./plots dir.
Usage: semu-fuzz-helper draw <base_configs.yml>
'''

import subprocess
import os
from ..utils import find_output_folders

plots_dir = 'plots'
time_format = '%d/%H:%M'
time_format_show = '%d/%H'
xtics = 4

import datetime

def format_difference_of_timestamp(timestamp_begin, timestamp_end, time_format='%d/%H:%M'):
    # Create a time difference object
    time_diff = datetime.timedelta(seconds=timestamp_begin - timestamp_end)
    if time_diff.days > 0:
        return None
    # Create a base time (it can be any reference time)
    base_time = datetime.datetime(2023, 1, 1, 0, 0, 0)
    # Add the time difference to the base time
    result_time = base_time + time_diff
    # Format the timestamp string
    formatted_timestamp = result_time.strftime(time_format)
    return formatted_timestamp

def draw_one_block(fuzzs_block_dir):
    # split fuzzs_block_dir as elf_dir and stat_dir, such as 'elf_dir/stat_dir/'
    elf_dir = os.path.dirname(fuzzs_block_dir)
    stat_dir = os.path.basename(fuzzs_block_dir)
    print('[*] Plot Block Coverage of %s...' % elf_dir, end="\t")

    # create plots dir
    if not os.path.exists(plots_dir):
        os.mkdir(plots_dir)

    # dirname
    fuzz_block_path = os.path.join(fuzzs_block_dir, "new_blocks.txt")
    plot_path = os.path.join(plots_dir, "plot-%s-%s" % (elf_dir.replace("/", "-"), stat_dir.replace("/", "-")))
    plot_png_path = plot_path + ".png"
    plot_dat_path = plot_path + ".dat"

    # read data
    data = []
    with open(fuzz_block_path, 'r') as f:
        for line in f:
            timestamp, value = line.strip().split('\t')[:2]
            data.append([int(timestamp), int(value)])

    # translate timestamp
    if len(data) <= 0:
        print(f"[-] No stat output in {stat_dir}")
        return None
    start_timestamp = data[0][0]
    data_index = 0
    for timestamp, _ in data:
        # date = format_difference_of_timestamp(timestamp, start_timestamp, time_format)
        date = timestamp - start_timestamp
        data[data_index][0] = date
        data_index += 1

    # write to dat file
    with open(plot_dat_path, 'w') as f:
        for i in range(data_index):
            f.write('{} {}\n'.format(data[i][0], data[i][1]))
    print(f"[+] Output coverage plot dat to {plot_dat_path}")
    
    global xtics
    xtics_second = 3600
    xrange_end = data[data_index-1][0]
    if xrange_end < 14400:
        xtics_second = 300 # 5 mins
    xrange_end = int(xrange_end/xtics_second)
    if xrange_end <= 0:
        print(f"[-] Too short duration in {stat_dir}, skip it.")
        return None
    # plot by timestamp, and only show the hour
    gnuplot_code = 'set term png;'
    gnuplot_code += f'set output "{plot_png_path}";'
    gnuplot_code += 'set xlabel "Time(hour)";'
    gnuplot_code += 'set ylabel "BBs";'
    gnuplot_code += f'set title "{elf_dir}" noenhanced;'
    gnuplot_code += f'set xtics {xtics};'
    gnuplot_code += f'set xrange [0:{xrange_end}];'
    gnuplot_code += f'plot "{plot_dat_path}" using ($1/{xtics_second}):2 with lines title "{stat_dir.rsplit("/",1)[-1]}" noenhanced,'

    try:
        output = subprocess.check_output(["gnuplot", "-e", gnuplot_code])
    except subprocess.CalledProcessError as e:
        print(f"[-] Gnuplot Error!")
        print(gnuplot_code)
    else:
        print(f"[+] Output coverage plot png to {plot_png_path}")
    return plot_dat_path


def draw(base_configs):
    for firmware_elfpath, base_config in base_configs.items():
        # set default model
        model = 'semu'
        if 'model' in base_config.keys():
            model = base_config['model']
        firmware_dir = os.path.dirname(firmware_elfpath)
        stat_path = os.path.join(firmware_dir, 'stat')
        # find_folders
        dirs = find_output_folders(firmware_dir, "stat")
        plot_dat_paths = []
        # draw all the blocks
        for stat_path in dirs:
            plot_dat_path = draw_one_block(stat_path)
            if plot_dat_path != None:
                plot_dat_paths.append([stat_path, plot_dat_path])
        # draw all the blocks as one plot
        print('[*] Plot All Blocks Coverage of %s...' % firmware_dir, end="\t")
        # create plots dir
        if not os.path.exists(plots_dir):
            os.mkdir(plots_dir)
        # dirname
        plot_path = os.path.join(plots_dir, "all-plot-%s" % firmware_dir.replace("/", "-"))
        plot_png_path = plot_path + ".png"
        plot_dat_path = plot_path + ".dat"
        # plot all the dat files
        global xtics
        gnuplot_code = 'set term png;'
        gnuplot_code += f'set output "{plot_png_path}";'
        gnuplot_code += 'set xlabel "Time(hour)";'
        gnuplot_code += 'set ylabel "BBs";'
        gnuplot_code += f'set title "{firmware_dir}" noenhanced;'
        gnuplot_code += f'set xtics {xtics};'
        gnuplot_code += 'set key right bottom;'
        gnuplot_code += 'plot '
        if len(plot_dat_paths) > 0:
            for plot_dat_path in plot_dat_paths:
                gnuplot_code += f'"{plot_dat_path[1]}" using ($1/3600):2 with lines title "{plot_dat_path[0].rsplit("/",1)[-1]}" noenhanced,'
        else:
            print(f"[-] No stat output in {firmware_dir}")
            continue
        gnuplot_code = gnuplot_code[:-1] + ';'
        try:
            output = subprocess.check_output(["gnuplot", "-e", gnuplot_code])
        except subprocess.CalledProcessError as e:
            print(f"[-] Gnuplot Error!")
            print(gnuplot_code)
        else:
            print(f"[+] Output coverage plot png to {plot_png_path}")
