import os
import sys
import zipfile
import r2pipe
import ctypes
import shutil

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

def log_info(msg): print(f"{BLUE}[INFO]{RESET} {msg}")
def log_success(msg): print(f"{GREEN}[OK]{RESET} {msg}")
def log_warn(msg): print(f"{YELLOW}[WARN]{RESET} {msg}")
def log_error(msg): print(f"{RED}[ERROR]{RESET} {msg}")

def is_apk(filename): return filename.endswith(".apk")
def has_slash(path): return '/' in path

def find_library_base(libname):
    try:
        with open("/proc/self/maps", "r") as maps:
            for line in maps:
                if libname in line:
                    addr = line.split("-")[0]
                    return int(addr, 16)
        return 0
    except Exception as e:
        log_error(f"Failed to read /proc/self/maps: {e}")
        return 0

def dump_section(mapped_addr, size, output_file):
    try:
        buf = ctypes.string_at(mapped_addr, size)
        with open(output_file, "wb") as f:
            f.write(buf)
        return True
    except Exception as e:
        return False

def run_radare2_strings(filepath):
    try:
        r2 = r2pipe.open(filepath, flags=["-e","log.quiet=true","-e","bin.cache=true","-e","log.level=0"])
        strings_output = r2.cmd("izzq")
        r2.quit()
        all_strings = []
        if strings_output:
            lines = strings_output.strip().split("\n")
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        paddr = parts[0]
                        string_value = " ".join(parts[3:])
                        all_strings.append((paddr, string_value))
        
        return all_strings
    except Exception as e:
        log_error(f"Error running radare2 strings on {filepath}: {e}")
        return []

def process_so(so_path, output_dir):
    libname = os.path.basename(so_path)

    section_info = {}
    try:
        r2 = r2pipe.open(so_path, flags=["-e","log.quiet=true","-e","bin.cache=true","-e","bin.relocs.apply=true","-e","log.level=0"])        
        sections = r2.cmdj("iSj")
        r2.quit()

        if sections:
            for section in sections:
                name = section.get("name")
                vaddr = section.get("vaddr")
                size = section.get("size")
                if name in [".data"]:
                    section_info[name] = {"vaddr": vaddr, "size": size}
        else:
            return

    except Exception as e:
        return

    if not section_info:
        return

    try:
        target_lib_handle = ctypes.CDLL(so_path)
    except OSError as e:
        log_error(f"[{libname}] failed: {e}")
        return

    target_lib_base_address = find_library_base(libname)
    if not target_lib_base_address:
        log_error(f"[{libname}] Failed to find runtime base address. Cannot dump sections.")
        return

    log_info(f"[{libname}] Emulated Base Address: 0x{target_lib_base_address:x}")

    dumped_files = []
    for name, info in section_info.items():
        vaddr_offset = info["vaddr"]
        size = info["size"]
        mapped_addr = target_lib_base_address + vaddr_offset
        sanitized_libname = libname.replace('/', '_')
        out_file = os.path.join(output_dir, f"{sanitized_libname}_x.bin")
        if dump_section(mapped_addr, size, out_file):
            dumped_files.append(out_file)

    all_unique_strings = {}
    for d_file in dumped_files:
        strings_from_dumped = run_radare2_strings(d_file)
        for paddr, string_value in strings_from_dumped:
            key = (paddr, string_value)
            all_unique_strings[key] = (paddr, string_value)

    sanitized_libname = libname.replace('/', '_')
    strings_output_file = os.path.join(output_dir, f"{sanitized_libname}_str.txt")

    sorted_strings = sorted(list(all_unique_strings.values()), key=lambda x: int(x[0], 16))
    with open(strings_output_file, "w", encoding="utf-8") as f:
        for paddr, string_value in sorted_strings:
            f.write(f"{paddr} {string_value}\n")

def main():
    if len(sys.argv) != 2:
        log_error(f"Usage: {sys.argv[0]} <path_to_apk>")
        sys.exit(1)

    apk_path = sys.argv[1]
    if not os.path.isfile(apk_path) or not is_apk(apk_path):
        log_error("Invalid APK file or not an APK.")
        sys.exit(1)

    section_dump_dir = os.path.join(os.path.dirname(apk_path), "dump")
    os.makedirs(section_dump_dir, exist_ok=True)

    temp_folder = os.path.abspath("tempfolder")
    if os.path.exists(temp_folder):
        log_info(f"Removing existing temporary folder: {temp_folder}")
        shutil.rmtree(temp_folder)
    os.makedirs(temp_folder)

    extracted_libs = []
    with zipfile.ZipFile(apk_path, "r") as zip_ref:
        for f in zip_ref.namelist():
            if f.startswith("lib/arm64-v8a/") and f.endswith(".so"):
                zip_ref.extract(f, temp_folder)
                extracted_libs.append(os.path.join(temp_folder, f))

    if not extracted_libs:
        shutil.rmtree(temp_folder)
        sys.exit(0)

    for full_path in extracted_libs:
        if os.path.isfile(full_path) and full_path.endswith(".so"):
            process_so(full_path, section_dump_dir)

    shutil.rmtree(temp_folder)
    log_success("All done.")

if __name__ == "__main__":
    main()