import os
import pefile
import time
import click

# ----------------------- global variables --------------------------

header_fields = ["DOS_HEADER.e_magic", "DOS_HEADER.e_cblp", "DOS_HEADER.e_cp", "DOS_HEADER.e_crlc",
                 "DOS_HEADER.e_cparhdr",
                 "DOS_HEADER.e_minalloc", "DOS_HEADER.e_maxalloc", "DOS_HEADER.e_ss", "DOS_HEADER.e_sp",
                 "DOS_HEADER.e_csum", "DOS_HEADER.e_ip", "DOS_HEADER.e_cs",
                 "DOS_HEADER.e_lfarlc", "DOS_HEADER.e_ovno", "DOS_HEADER.e_res", "DOS_HEADER.e_oemid",
                 "DOS_HEADER.e_oeminfo", "DOS_HEADER.e_res2",
                 "DOS_HEADER.e_lfanew", "FILE_HEADER.Machine", "FILE_HEADER.NumberOfSections",
                 "FILE_HEADER.TimeDateStamp", "FILE_HEADER.PointerToSymbolTable",
                 "FILE_HEADER.NumberOfSymbols", "FILE_HEADER.SizeOfOptionalHeader", "FILE_HEADER.Characteristics",
                 "OPTIONAL_HEADER.Magic", "OPTIONAL_HEADER.MajorLinkerVersion", "OPTIONAL_HEADER.MinorLinkerVersion",
                 "OPTIONAL_HEADER.SizeOfCode",
                 "OPTIONAL_HEADER.SizeOfInitializedData", "OPTIONAL_HEADER.SizeOfUninitializedData",
                 "OPTIONAL_HEADER.AddressOfEntryPoint",
                 "OPTIONAL_HEADER.BaseOfCode", "OPTIONAL_HEADER.ImageBase", "OPTIONAL_HEADER.SectionAlignment",
                 "OPTIONAL_HEADER.FileAlignment",
                 "OPTIONAL_HEADER.MajorOperatingSystemVersion", "OPTIONAL_HEADER.MinorOperatingSystemVersion",
                 "OPTIONAL_HEADER.MajorImageVersion",
                 "OPTIONAL_HEADER.MinorImageVersion", "OPTIONAL_HEADER.MajorSubsystemVersion",
                 "OPTIONAL_HEADER.MinorSubsystemVersion", "OPTIONAL_HEADER.Reserved1",
                 "OPTIONAL_HEADER.SizeOfImage", "OPTIONAL_HEADER.SizeOfHeaders", "OPTIONAL_HEADER.CheckSum",
                 "OPTIONAL_HEADER.Subsystem", "OPTIONAL_HEADER.DllCharacteristics",
                 "OPTIONAL_HEADER.SizeOfStackReserve", "OPTIONAL_HEADER.SizeOfStackCommit",
                 "OPTIONAL_HEADER.SizeOfHeapReserve", "OPTIONAL_HEADER.SizeOfHeapCommit",
                 "OPTIONAL_HEADER.LoaderFlags", "OPTIONAL_HEADER.NumberOfRvaAndSizes"]
start_time = time.time()

# ------------------------ end of global variables --------------------

def extract_header_field(pe, header_field, default_value):
    sub_header, field_name = header_field.split('.')
    try:
        sub_header_feilds = getattr(pe, sub_header)
        field = getattr(sub_header_feilds, field_name)
        return field
    except:
        return default_value


@click.command()
@click.option('--path', required=True, help='path of samples')
@click.option('--header_fields_outputfile', default='header_fields.txt',
              help='output file name for storing header fields')
@click.option('--section_names_outputfile', default='section_names.txt',
              help='output file name for storing section names')
def Feature_extractor(path, header_fields_outputfile, section_names_outputfile):
    fields = []
    samples = os.listdir(path)
    header_fields_file = open(header_fields_outputfile, 'w')
    section_names_file = open(section_names_outputfile, 'w')
    for sample in samples:
        try:
            pe = pefile.PE(path + sample)

            # extracting all fields of DOS header,File header, and Optional header
            for field in header_fields:
                fields.append(extract_header_field(pe, field, 0))

            # storing extracted fields
            for field in fields:
                header_fields_file.write(str(field) + "\t,")
            header_fields_file.write(sample + "\n")
            fields = []

            # extracting section names
            try:
                sections = pe.sections
                for section in sections:
                    name = (section.Name).decode('utf-8')
                    name = name.replace('\x00', '')
                    section_names_file.write(name + ",")
                section_names_file.write(sample + "\n")
            except:
                print('interior {}'.format(sample))
                section_names_file.write(',' + sample + "\n")
                continue

        except Exception as e:
            print(e)
            print('{} is not a pe file'.format(sample))

    end_time = time.time()
    print('feature extraction time: {} seconds'.format(end_time - start_time))


if __name__ == '__main__':
    Feature_extractor()
