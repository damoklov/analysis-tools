"""
Opcode Sequence Analyzer and Matcher
Version: 0.1
Usage: python3 analyzer.py -f binary-1 binary-2 ... binary-n [-e entropy]
"""

import binascii
import re
import math
import pprint
import argparse


def extract_sequences(hexdump, regex, entropy):
	matches = re.findall(regex, hexdump)
	matches_with_high_entropy = [item for item in matches if shannons_entropy(item) > float(entropy)]
	mean = sum(list(map(shannons_entropy, matches)))/len(matches)
	matches_entropy = {pattern: shannons_entropy(pattern) for pattern in matches}
	try:
		leftover = hexdump[-(len(hexdump) - len(''.join(matches))):]
	except:
		leftover = ''
	return tuple(matches_with_high_entropy)


def hexdump_files(filenames, entropy=0.0):
	hexdumps = list()
	for filename in filenames:
		with open(filename, 'rb') as f:
			content = f.read()
		hexdump = binascii.hexlify(content).decode('utf-8')
		extracted_sequences = extract_sequences(hexdump, '[a-f0-9]{32}', entropy)
		hexdumps.append(extracted_sequences)
	return hexdumps


def shannons_entropy(string):
	prob = [float(string.count(c))/len(string) for c in dict.fromkeys(list(string))]
	entropy = - sum([p*math.log(p)/math.log(2.0) for p in prob])
	return entropy


def compare_sequences(list_of_sets_of_sequences):
	intersection = set(list_of_sets_of_sequences[0]).intersection(*list_of_sets_of_sequences[1:])
	pprint.pprint(intersection)


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-f', '--files', nargs="+")
	parser.add_argument('-e', '--entropy', default=0.0)
	files_to_compare = parser.parse_args().files
	entropy = parser.parse_args().entropy
	hexdumps = hexdump_files(files_to_compare, entropy)
	compare_sequences(hexdumps)


if __name__ == '__main__':
	main()
