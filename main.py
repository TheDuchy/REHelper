import argparse, os, sys
from terminaltables import AsciiTable
import modules.utils as util
import modules.elf as elf
import modules.pe as pe


parser = argparse.ArgumentParser(description='REHelper is an utility for initial binary analysis.')

parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Verbose output")
parser.add_argument('-f', '--file', metavar="filename", dest="inname", help="File to process", required=True)

args = parser.parse_args()

if not os.path.isfile(args.inname):
    sys.exit("The input file does not exist!")

with open(args.inname, "rb") as f:
    magic = f.read(4)
    if magic == b"\x7FELF":
        elf.print_basic_info(args.inname)
    else:
        pe.print_basic_info(args.inname)

if args.verbose:
    # variables
    interesting_strings = util.file_interesting_strings(args.inname)
    tmp = []
    y_packer = ""
    y_malware = ""
    y_antitricks = ""
    y_crypto = ""
    y_cve = ""
    # logic
    ## Interesting strings
    for x in interesting_strings:
        string = ""
        for c, y in enumerate(interesting_strings[x]):
            if c % 4 == 0 and c > 0:
                string += "\n"
            string += y + " "
            if not string.strip():
                string = util.RED + "None" + util.RESET
            tmp.append([x + ":", string])

    strings_table = [
                ["Interesting Strings", "STILL IN BETA ;)"],
            ]

    for x in tmp:
        strings_table.append(x)
    tmp = []

    ## YARA
    for c, match in enumerate(util.yara_packer(args.inname)):
        if c % 4 == 0 and c > 0:
            y_packer += "\n"
        y_packer += str(match) + " "
    for c, match in enumerate(util.yara_malware(args.inname)):
        if c % 4 == 0 and c > 0:
            y_malware += "\n"
        y_malware += str(match) + " "
    for c, match in enumerate(util.yara_antitricks(args.inname)):
        if c % 6 == 0 and c > 0:
            y_antitricks += "\n"
        y_antitricks += str(match) + " "
    for c, match in enumerate(util.yara_cve(args.inname)):
        if c % 6 == 0 and c > 0:
            y_cve += "\n"
        y_cve += str(match) + " "
    for c, match in enumerate(util.yara_crypto(args.inname)):
        if c % 6 == 0 and c > 0:
            y_crypto += "\n"
        y_crypto += str(match) + " "
    yara_table = [
        ["Yara category", "Match"],
    ]
    if not y_packer.strip():
        y_packer = util.RED + "None" + util.RESET
    if not y_malware.strip():
        y_malware = util.RED + "None" + util.RESET
    if not y_cve.strip():
        y_cve = util.RED + "None" + util.RESET
    if not y_antitricks.strip():
        y_antitricks = util.RED + "None" + util.RESET
    if not y_crypto.strip():
        y_crypto = util.RED + "None" + util.RESET
    yara_table.append(["Signatures:", y_packer])
    yara_table.append(["Malware:", y_malware])
    yara_table.append(["CVE:", y_cve])
    yara_table.append(["Antitricks:", y_antitricks])
    yara_table.append(["Crypto:", y_crypto])


    # print
    print(AsciiTable(table_data=strings_table, ).table)
    print("")
    print(AsciiTable(table_data=yara_table, ).table)
