import pefile
import json
from pathlib import Path
import argparse

parser = argparse.ArgumentParser('Enhance VerInfo')

parser.add_argument('files_json', help='File to enhance')

args = parser.parse_args()

file_json_path = Path(args.files_json)
new_file_json_path = Path(file_json_path.name.split(file_json_path.suffix)[0] + '.enhanced' + file_json_path.suffix)

files = json.loads(file_json_path.read_bytes())

for i, file in enumerate(files):
    print(f"{int(i / len(files) * 100)}% : {file['Name']} ")

    try:
        pe = pefile.PE(file['VersionInfo']['FileName'], fast_load=True)
    except pefile.PEFormatError as ex:
        print(ex)
        continue

    
    file['timestamp'] = pe.FILE_HEADER.TimeDateStamp
    file['size'] = pe.OPTIONAL_HEADER.SizeOfImage
    

    # only imports directory
    pe.parse_data_directories([1])

    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        continue
    
    import_dlls = []
    imports_funcs = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        import_dlls.append(entry.dll.decode())
        
        for imp in entry.imports:
            if imp.name:
                imports_funcs.append(imp.name.decode())

    file['import_dlls'] = import_dlls
    file['import_funcs'] = imports_funcs

    
new_file_json_path.write_text(json.dumps(files, indent=4))
