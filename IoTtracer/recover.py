import angr
import struct
import sys
import shutil

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python3 recover.py <target> <probe_info>")
        sys.exit(1)

    targetname = sys.argv[1]
    probe_info_file = sys.argv[2]
    print(f"Doing: {targetname} {probe_info_file}")

    p = angr.Project(targetname, auto_load_libs=False, except_missing_libs=True, main_opts={'base_addr': 0x0})
    targetarch = p.arch.name
    targetend = p.arch.memory_endness
    print(targetarch, targetend)

    if targetarch in ("X86", "AMD64") :
        probe_bytes = b'\xcc'
        bytes_num = 1
    elif targetarch in ("ARMEL", "ARMHF", "ARM") :
        if targetend == 'Iend_LE':
            probe_bytes = struct.pack('<I', 0xe7f001f0)
        else:
            probe_bytes = struct.pack('>I', 0xe7f001f0)
        bytes_num = 4
    elif targetarch == "AARCH64" :
        if targetend == 'Iend_LE':
            probe_bytes = struct.pack('<I', 0xd4200000)
        else:
            probe_bytes = struct.pack('>I', 0xd4200000)
        bytes_num = 4
    elif targetarch in ("MIPS32", "MIPS64") :
        if targetend == 'Iend_LE':
            probe_bytes = struct.pack('<I', 0x0005000d)
        else:
            probe_bytes = struct.pack('>I', 0x0005000d)
        bytes_num = 4
    # print(probe_bytes.hex())

    probe_info = []
    with open(probe_info_file, 'rb') as f:
        data = f.read()

    data = data.strip()
    for probe_data in data.split(b'\n0x'):
        # print(probe_data)
        info = probe_data.split(b': ', maxsplit=1)
        d = {"addr": int(info[0], 16),
             "ins": info[1]}
        probe_info.append(d)
    # print(probe_info)

    origin_target = targetname + '_origin'
    shutil.copy(targetname, origin_target)

    with open(origin_target, 'rb+') as f:
        for d in probe_info:
            f.seek(d["addr"])
            data = f.read(bytes_num)

            if data == probe_bytes:
                f.seek(d["addr"])
                f.write(d["ins"])
                
    
    print(f"✅ Successfully saved {origin_target}")