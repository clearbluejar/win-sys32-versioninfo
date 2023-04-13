import pefile
import json
from pathlib import Path
import argparse
import concurrent.futures
from multiprocessing import cpu_count

MAX_WORKERS = cpu_count()

def get_microsoft_download_url(filename, timestamp, virtual_size):

    assert filename is not None
    assert timestamp is not None
    assert virtual_size is not None

    timestamp = format(timestamp, '08X')
    virtual_size = format(virtual_size, 'X')

    return f'https://msdl.microsoft.com/download/symbols/{filename}/{timestamp}{virtual_size}/{filename}'

def enhance_file(file: dict, proc_files, modules):

    file['running'] = False
    # match on path
    
    if proc_files.get(file['VersionInfo']['FileName']) is not None:
        for info in proc_files[file['VersionInfo']['FileName']]:
            file.setdefault('username', []).append(info['username'])            
            file.setdefault('commandline', []).append(info['commandline'])
            file.setdefault('modcount', []).append(len(info['modules']))
            file['running'] = True
            
        # dedupe
        file['username'] = list(set(file['username']))
        file['commandline'] = list(set(file['commandline']))
        file['modcount'] = list(set(file['modcount']))

    
    if modules.get(file['VersionInfo']['FileName']) is not None:
        for mod_info in modules[file['VersionInfo']['FileName']]:
            file.setdefault('parent', []).append(mod_info['parent'])            
            file.setdefault('parentUser', []).append(mod_info['parentUser'])
            file.setdefault('parentCommand', []).append(mod_info['parentCommand'])
            file['loadedmodule'] = True

        # dedupe
        file['parent'] = list(set(file['parent']))
        file['parentUser'] = list(set(file['parentUser']))
        file['parentCommand'] = list(set(file['parentCommand']))

            
    pe = None    
    try:
        pe = pefile.PE(file['VersionInfo']['FileName'], fast_load=True)
    except pefile.PEFormatError as ex:
        print(ex)
        
    if pe is None:
        print(f"Error parsing PE for {file['Name']}")
        return file['Name']
   
    file['timestamp'] = pe.FILE_HEADER.TimeDateStamp
    file['size'] = pe.OPTIONAL_HEADER.SizeOfImage
    file['machine'] = pe.FILE_HEADER.Machine

    file['url'] = get_microsoft_download_url(file['Name'],file['timestamp'],file['size'])

    # only imports directory
    pe.parse_data_directories([1])

    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return file['Name']
    
    import_dlls = []
    imports_funcs = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        import_dlls.append(entry.dll.decode())
        
        for imp in entry.imports:
            if imp.name:
                imports_funcs.append(imp.name.decode())

    file['import_dlls'] = import_dlls
    file['import_funcs'] = imports_funcs

    return file['Name']

parser = argparse.ArgumentParser('Enhance VerInfo')

parser.add_argument('verinfo', help='verinfo json')
parser.add_argument('procinfo', help='verinfo json')
parser.add_argument('output', help='output file')

args = parser.parse_args()

file_json_path = Path(args.verinfo)
proc_json_path = Path(args.procinfo)
new_file_json_path = Path(args.output)

files = json.loads(file_json_path.read_bytes())
procs = json.loads(proc_json_path.read_bytes())

proc_files = {}
modules = {}
# index by path
for proc,info in procs.items():
    proc_files.setdefault(info['path'], []).append(info)
    if info['modules']:
        for module in info['modules']:
            print(module)
            mod_info = { 'parent': info['path'], 'parentUser': info['username'], 'parentCommand' : info['commandline'] }
            modules.setdefault(module['FileName'], []).append(mod_info)


count = 0 
with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    futures = (executor.submit(enhance_file, files[sha256], proc_files, modules) for sha256 in files)
    
    for future in concurrent.futures.as_completed(futures):
        count += 1        
        name = future.result()
        print(f"{int(count / len(files) * 100)}% : {name} ")

        
new_file_json_path.write_text(json.dumps(files))
