
def calling_convention(arch, os):
    if arch == 'x86-64':
        if os == 'linux':
            return 'sysv'
        elif os == 'windows':
            return 'win64'
        
    raise ValueError('Unsupported OS')

def get_abi_register(abi):
    if abi == 'sysv':
        return ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')
    elif abi == 'win64':
        return ('rcx', 'rdx', 'r8', 'r9')
    
    raise ValueError('Unsupported ABI')