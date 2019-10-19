# PE shit
import pefile
# ASCII shit
from terminaltables import AsciiTable
# Common shit
from modules.utils import GREEN, RED, RESET, file_MD5sum, file_ssdeepsum, file_sha1sum, file_sha256sum, tinyurl, file_size, file_all_strings, file_interesting_strings, file_entropy

def print_basic_info(filename: str) -> None:
    pe_file = pefile.PE(filename, fast_load=True) # ELF object

    # variables
    sections = ""
    debug = RED + "No" + RESET
    fileMD5 = file_MD5sum(filename)
    filesha1 = file_sha1sum(filename)
    filesha256 = file_sha256sum(filename)
    fileSSDEEP = file_ssdeepsum(filename)
    vtlink = tinyurl("https://www.virustotal.com/gui/file/" + filesha256)
    

    # logic
    if not vtlink:
        vtlink = "https://www.virustotal.com/gui/file/" + filesha256
    for c, x in enumerate(pe_file.sections):
        if len(x.Name) > 0:
            sections += "{}{} {}({}) ".format(
                                        GREEN, x.Name.replace(b"\x00", b"").decode("UTF-8"), RESET,
                                        hex(x.SizeOfRawData))
        if c % 4 == 0 and c > 0:
            sections += "\n"
    
    if not sections:
        sections = RED + "No sections found" + RESET
    # has debug info?
    if hasattr(pe_file, 'DIRECTORY_ENTRY_DEBUG'):
        debug = GREEN + "Yes" + RESET

    info_table = [
        ["Filename:", filename],
        ["Filesize:", file_size(filename)],
        ["Filetype:", GREEN + "PE " + str(pefile.MACHINE_TYPE[pe_file.FILE_HEADER.Machine] + RESET)],
        ["Subsystem:", str(GREEN + pefile.SUBSYSTEM_TYPE[pe_file.OPTIONAL_HEADER.Subsystem] + RESET)],
        ["MD5: ", fileMD5],
        ["SHA1: ", filesha1],
        ["SHA256: ", filesha256],
        ["SSDEEP:", fileSSDEEP],
        ["VT link:", vtlink],
        ["Symbols:", debug],
        ["Entropy:", str(file_entropy(filename))],
        ["Sections:\n(with size)", sections],
        ["Entrypoint:", "{}".format(hex(pe_file.OPTIONAL_HEADER.AddressOfEntryPoint))]
    ]

    print("")
    print(AsciiTable(title="Basic Information", table_data=info_table, ).table)
    print("")
