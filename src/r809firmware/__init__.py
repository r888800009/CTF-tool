import subprocess
import os


def invoke_binwalk(file_path):
    # TODO: cache binwalk results
    return subprocess.Popen(["binwalk", file_path], stdout=subprocess.PIPE)


def get_mount_hint(file_path, offset, mount_point="/mnt"):
    return f"sudo mount -o loop,offset={offset} {file_path} {mount_point}"


def get_offset(binwalk_line):
    return int(binwalk_line.split()[0])


def list_file_system(file_path):
    # extend file_path to full path
    file_path = os.path.expanduser(file_path)
    proc = invoke_binwalk(file_path)
    for line in iter(proc.stdout.readline, b""):
        if b"filesystem" in line.lower():
            print(line.decode())
            print("\t" + get_mount_hint(file_path, get_offset(line)))

    proc.stdout.close()
    proc.wait()


if __name__ == "__main__":
    import sys

    list_file_system(sys.argv[1])
