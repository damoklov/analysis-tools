"""
Entropy Analyzer and Visualizer
Version: 0.1
Usage: python3 entropy.py -f binary [-s size]
"""

import argparse
import binascii
import math
import matplotlib.pyplot as plt
import lief


def h(block_data):
    entropy = 0
    for x in range(256):
        p_x = block_data.count(x) / len(block_data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def block_entropy(block_data, block_size):
    for x in range(0, len(block_data) // block_size):
        start = x * block_size
        end = start + block_size
        yield end, h(block_data[start:end])


def hexlify_element(n):
    x = '%x' % (n,)
    return ('0' * (len(x) % 2)) + x


def main(file, size, output):
    binary = lief.parse(file)
    content = ''.join(list(map(lambda x: hexlify_element(x), binary.get_section("__text").content)))
    content = binascii.unhexlify(content)
    binary_info = dict()
    binary_info['Segments'] = []
    for segment in binary.segments:
        segment_info = {'Name': segment.name,
                        'Virtual_address': hex(segment.virtual_address),
                        'Virtual_size': hex(segment.virtual_size),
                        'Size': hex(segment.size),
                        'Number_of_sections': len(segment.sections),
                        'Sections': []}
        if len(segment.sections) > 0:
            for section in segment.sections:
                section_info = {'Name': section.name,
                                'Entropy': section.entropy}
                segment_info['Sections'].append(section_info)
        binary_info['Segments'].append(segment_info)
    try:
        entropy_list = []
        data = content
        for pos, b in block_entropy(data, size):
            entropy_list.append((pos, b))
        plt.figure(figsize=(20, 20))
        plt.fill_between(list(zip(*entropy_list))[0], list(zip(*entropy_list))[1], alpha=0.30, color='green')
        plt.grid()
        plt.xticks(list(zip(*entropy_list))[0])
        plt.plot(*zip(*entropy_list), marker='o', color='g')
        plt.savefig(output)
    except Exception as e:
        print('Failed execution. Unexpected error:')
        print(e)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True)
    parser.add_argument('-s', '--size', default=256, type=int)
    parser.add_argument('-o', '--output', default="graph.png")
    args = parser.parse_args()
    main(args.file, args.size, args.output)
