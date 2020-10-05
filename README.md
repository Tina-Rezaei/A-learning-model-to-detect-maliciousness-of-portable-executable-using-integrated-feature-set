# A-learning-model-to-detect-maliciousness-of-portable-executable-using-integrated-feature-set


Implementation of "A learning model to detect maliciousness of portable executable using integrated feature set."

# RUN
extract_header_fields.py extracts all header fields of Dos Header, File Header, and Optional Header of each file and stores them in the specified output file. It also extracts all section names of each file and stores them in another specified output file. You need to run it for your malware samples and benign samples separately.
```
python extract_header_fields.py --path path_of_samples --header_fields_outputfile path_of_output_file_for_header_fields --section_names_outputfile path_of_output_file_for_section_names

```
After that, you need to run main.py. It takes the path of malware and benign samples, and four other files were built in the previous step.

```
python main.py --malwarepath path_of_malware --benignpath path_of_benign_samples --benignheaderfieldspath path_of_benign_output_file_for_header_fields --malwareheaderfieldspath path_of_malware_output_file_for_header_fields --malwaresectionnamespath path_of_malware_output_file_for_section_names --benignsectionnamespath path_of_benign_output_file_for_section_names 

```

# Examples
```
python extract_header_fields.py --path ./malware_samples --header_fields_outputfile malware_header_fields.txt --section_names_outputfile malware_section_names.txt
python extract_header_fields.py --path ./benign_samples --header_fields_outputfile benign_header_fields.txt --section_names_outputfile benign_section_names.txt

python main.py --malwarepath ./malware_samples --benignpath ./benign_samples --benignheaderfieldspath benign_header_fields.txt --malwareheaderfieldspath malware_header_fields.txt --malwaresectionnamespath malware_section_names.txt --benignsectionnamespath benign_section_names.txt

```

