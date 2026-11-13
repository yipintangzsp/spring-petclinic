import errno
import unittest
from sandbox import network_filter


def evaluate(program, syscall, family=2, kind=1, protocol=0, arch=0xc00000b7):
    data = {0: syscall, 4: arch, 16: family, 24: kind, 32: protocol}
    pc = acc = 0
    while pc < len(program):
        code, yes, no, value = program[pc]
        if code == 0x20:
            acc = data[value]
        elif code == 0x15:
            pc += yes if acc == value else no
        elif code == 0x54:
            acc &= value
        elif code == 0x06:
            return value
        else:
            raise AssertionError(code)
        pc += 1
    raise AssertionError('No verdict')


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.program = network_filter('aarch64')

    def test_tcp_and_unix_only(self):
        for family in [2, 10]:
            for protocol in [0, 6]:
                self.assertEqual(evaluate(self.program, 198, family, 1 | 0x80000, protocol), 0x7fff0000)
        self.assertEqual(evaluate(self.program, 198, 1), 0x7fff0000)
        self.assertEqual(evaluate(self.program, 199, 1), 0x7fff0000)

    def test_datagram_raw_vsock_and_unsupported_families_denied(self):
        for family, kind, protocol in [(2, 2, 0), (10, 2, 0), (2, 3, 0), (17, 3, 0), (40, 1, 0), (44, 1, 0), (2, 1, 132)]:
            self.assertEqual(evaluate(self.program, 198, family, kind, protocol), 0x50000 | errno.EPERM)
        self.assertEqual(evaluate(self.program, 199, 40), 0x50000 | errno.EPERM)

    def test_io_uring_bypass_denied(self):
        for syscall in [425, 426, 427]:
            self.assertEqual(evaluate(self.program, syscall), 0x50000 | errno.EPERM)

    def test_compat_abi_killed_and_other_syscalls_keep_runtime_default(self):
        self.assertEqual(evaluate(self.program, 198, arch=0x40000028), 0x80000000)
        self.assertEqual(evaluate(self.program, 172), 0x7fff0000)

    def test_unknown_architecture_fails_closed(self):
        with self.assertRaises(RuntimeError):
            network_filter('x86_64')
