"""Fail-closed unprivileged network sandbox, inherited by Node/Terraform children."""
import ctypes
import errno
import json
import os
import platform
import sys


def network_filter(architecture):
    # Linux AArch64 seccomp_data: arch@4, syscall@0, arguments@16.
    if architecture != 'aarch64':
        raise RuntimeError('Pinned runtime requires native ARM64')
    program = []
    labels = {}
    def emit(code, value, yes=None, no=None):
        program.append([code, 0, 0, value, yes, no])
    def mark(name):
        labels[name] = len(program)
    emit(0x20, 4)
    emit(0x15, 0xc00000b7, 'syscall', 'kill')
    mark('kill'); emit(0x06, 0x80000000)
    mark('syscall'); emit(0x20, 0)
    emit(0x15, 425, 'deny', 'uring_enter')
    mark('uring_enter'); emit(0x15, 426, 'deny', 'uring_register')
    mark('uring_register'); emit(0x15, 427, 'deny', 'socket')
    mark('socket'); emit(0x15, 198, 'family', 'socketpair')
    mark('socketpair'); emit(0x15, 199, 'unix_pair', 'allow')
    mark('unix_pair'); emit(0x20, 16); emit(0x15, 1, 'allow', 'deny')
    mark('family'); emit(0x20, 16)
    emit(0x15, 1, 'allow', 'inet')
    mark('inet'); emit(0x15, 2, 'type', 'inet6')
    mark('inet6'); emit(0x15, 10, 'type', 'deny')
    mark('type'); emit(0x20, 24); emit(0x54, 0xf)
    emit(0x15, 1, 'protocol', 'deny')
    mark('protocol'); emit(0x20, 32); emit(0x15, 0, 'allow', 'tcp')
    mark('tcp'); emit(0x15, 6, 'allow', 'deny')
    mark('deny'); emit(0x06, 0x00050000 | errno.EPERM)
    mark('allow'); emit(0x06, 0x7fff0000)
    result = []
    for i, (code, jt, jf, value, yes, no) in enumerate(program):
        if yes is not None:
            jt, jf = labels[yes] - i - 1, labels[no] - i - 1
            if not (0 <= jt < 256 and 0 <= jf < 256):
                raise RuntimeError('Invalid forward-only BPF program')
        result.append((code, jt, jf, value))
    return result


def enforce():
    if os.geteuid() != 65532:
        raise RuntimeError('Runtime must start unprivileged')
    lib = ctypes.CDLL(None, use_errno=True)
    lib.syscall.restype = ctypes.c_long
    if lib.prctl(39, 0, 0, 0, 0) != 1:
        raise RuntimeError('NoNewPrivileges must be enabled by the container runtime')
    abi = lib.syscall(444, 0, 0, 1)
    if abi < 6:
        raise RuntimeError('Landlock network and IPC scopes required; no permissive fallback')
    class Rules(ctypes.Structure):
        _fields_ = [('filesystem', ctypes.c_uint64), ('network', ctypes.c_uint64), ('scoped', ctypes.c_uint64)]
    class Port(ctypes.Structure):
        _fields_ = [('access', ctypes.c_uint64), ('port', ctypes.c_uint64)]
    rules = Rules(0, 3, 3)
    fd = lib.syscall(444, ctypes.byref(rules), ctypes.sizeof(rules), 0)
    if fd < 0:
        raise OSError(ctypes.get_errno(), 'Landlock ruleset creation failed')
    try:
        port = Port(2, 6443)
        if lib.syscall(445, fd, 2, ctypes.byref(port), 0) != 0:
            raise OSError(ctypes.get_errno(), 'Landlock port rule failed')
        if lib.syscall(446, fd, 0) != 0:
            raise OSError(ctypes.get_errno(), 'Landlock restriction failed')
    finally:
        os.close(fd)
    class Filter(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte), ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]
    class Program(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ushort), ('filters', ctypes.POINTER(Filter))]
    values = network_filter(platform.machine())
    instructions = (Filter * len(values))(*(Filter(*x) for x in values))
    program = Program(len(values), instructions)
    if lib.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'Additional seccomp filter failed')
    return {'landlock_abi': abi, 'tcp_connect_ports': [6443], 'tcp_bind_denied': True,
            'udp_raw_vsock_denied': True, 'io_uring_denied': True, 'no_new_privileges': True}


if __name__ == '__main__':
    result = enforce()
    os.makedirs('/work', exist_ok=True)
    with open('/work/sandbox.json', 'x', encoding='utf8') as handle:
        json.dump(result, handle)
    if len(sys.argv) < 2:
        raise RuntimeError('Explicit child command required')
    os.execvp(sys.argv[1], sys.argv[1:])
