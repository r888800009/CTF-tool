import subprocess


def invoke_binwalk(file_path):
    # TODO: cache binwalk results
    return subprocess.Popen(["binwalk", file_path], stdout=subprocess.PIPE)


def get_mount_hint(file_path, offset, mount_point="/mnt"):
    return f"sudo mount -o loop,offset={offset} {file_path} {mount_point}"


def get_offset(binwalk_line):
    return int(binwalk_line.split()[0])


def list_file_system(file_path):
    for line in iter(invoke_binwalk(file_path).stdout.readline, ""):
        if b"filesystem" in line.lower():
            print(line.decode())
            print("\t" + get_mount_hint(file_path, get_offset(line)))


if __name__ == "__main__":
    import sys

    list_file_system(sys.argv[1])
