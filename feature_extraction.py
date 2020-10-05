import os
import pefile
import subprocess


normal_section_names = ['.text', '.rdata', '.data', '.pdata', '.rsrc', '.idata', '.bss', '.code', '.edata']
architecture_page_size = 4096
X = []
Y = []

def entropy(name, path):
    entropy_list = []
    entropy = subprocess.check_output("ent '{}' | head -n 1 | cut -d' ' -f 3".format((path + name)),
                                      shell=True).decode('utf8')
    entropy_list.append(entropy[0:-1])

    pe = pefile.PE(path + name)
    text_flag = False
    data_flag = False
    for section in pe.sections:
        try:
            section_name = (section.Name).decode('utf-8')
            section_name = section_name.replace('\x00', '')
            if section_name == '.text':
                text_entropy = section.get_entropy()
                text_flag = True
            elif section_name == '.data':
                data_entropy = section.get_entropy()
                data_flag = True
        except:
            continue
    entropy_list.append(text_entropy if text_flag else -1)
    entropy_list.append(data_entropy if data_flag else -1)

    return entropy_list


def compilation_time(timedatestamp):
    """
    :param timedatestamp:
    it calculate the yaer that file was compiled
    :return:
    0, if the calculated year is valid
    1, if the calculated year is invalid
    """
    timedatestamp = int(timedatestamp)
    past_hours = timedatestamp / 3600
    past_days = past_hours / 24
    past_years = past_days // 365
    year_of_compile = 1370 + past_years
    if 2019 > year_of_compile > 1980:
        return 0
    else:
        return 1


def section_name_checker(section_names):
    """
    :param section_names:
    an array of section names of a program
    :return:
    a 1*2d array that indicate number of nonsuspicious sections and number of suspicious sections,respectively
    """
    number_of_suspicious_names = 0
    number_of_nonsuspicious_names = 0
    for name in section_names:
        if name in normal_section_names:
            number_of_nonsuspicious_names += 1
        else:
            number_of_suspicious_names += 1

    return number_of_suspicious_names, number_of_nonsuspicious_names


def extract_file_size(name, path):
    file_size = os.path.getsize(path + name)
    return file_size


def extract_file_info(name, path):
    pe = pefile.PE(path + name)
    try:
        fileinfo = pe.FileInfo
        return 1
    except:
        return 0


def Image_Base_checker(imagebase):
    if imagebase == 4194304 or imagebase == 65536 or imagebase == 268435456:
        return 1
    return 0


def sectionalignment_checker(sectionalignment, filealignment):
    if sectionalignment == 4096:
        return 0
    if sectionalignment >= filealignment:
        return 0
    else:
        return 1


def filealignment_checker(sectionalignment, filealignment):
    if filealignment >= 512 and filealignment <= 65536:
        return 0
    if sectionalignment < architecture_page_size and sectionalignment == filealignment:
        return 0
    elif sectionalignment < architecture_page_size and sectionalignment != filealignment:
        return 1
    return 1


def sizeofimage_checker(sizeofimage, section_alignment):
    if sizeofimage % section_alignment != 0:
        return 1
    return 0


def size_of_header_checker(name, path):
    pe = pefile.PE(os.path.join(path, name))
    msdos_stub_size = pe.DOS_HEADER.e_lfanew
    signature = pe.NT_HEADERS.sizeof()
    file_header = pe.FILE_HEADER.sizeof()
    optional_header = pe.OPTIONAL_HEADER.sizeof()
    section_header = sum([section.__format_length__ for section in pe.sections])

    total = msdos_stub_size + signature + file_header + optional_header + section_header
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    total = total if total % file_alignment == 0 else file_alignment * (total // file_alignment + 1)

    result = int(pe.OPTIONAL_HEADER.SizeOfHeaders == total)

    return result
