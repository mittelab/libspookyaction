import glob
import os.path
import subprocess
import shutil
import sys

import serial
import time
from typing import List, Tuple, Optional
import re

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

ADDRESS_RE = re.compile(r'0x[0-9a-f]{8}', re.IGNORECASE)
VERSION_RE = re.compile(r'\d+\.\d+\.\d+')
BACKTRACE_RE = re.compile(r'^Backtrace:(\s+0x[a-f0-9]{8}:0x[a-f0-9]{8})*', re.IGNORECASE)
SUCCESS_RE = re.compile(r':\s+Returned from app_main\(\)', re.IGNORECASE)
ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
TEST_RESULT_RE = re.compile(r'^\s*assertions:\s*(\d+\s*\|\s*\d+)\s*', re.IGNORECASE)


# Guru Meditation Error: Core  0 panic'ed (StoreProhibited). Exception was unhandled. Adapted from
# https://github.com/espressif/esp-idf-monitor/blob/master/esp_idf_monitor/base/pc_address_matcher.py
# Released under Apache license
class PCAddrTranslator:
    elf_path: Optional[str]
    intervals: List[Tuple[int, int]]

    def __init__(self, elf_path: Optional[str]):
        self.elf_path = elf_path
        self.intervals = []
        if elf_path is None:
            return
        if not os.path.isfile(elf_path):
            return
        with open(elf_path, 'rb') as fp:
            # Is this an ELF file?
            elf_magic = fp.read(4)
            if elf_magic != b'\x7fELF':
                raise NotImplementedError('Not an ELF file')
            fp.seek(0)

            elf = ELFFile(fp)

            for section in elf.iter_sections():
                if section['sh_flags'] & SH_FLAGS.SHF_EXECINSTR:
                    start = section['sh_addr']
                    size = section['sh_size']
                    end = start + size
                    self.intervals.append((start, end))
        self.intervals.sort()

    def __contains__(self, addr: int):
        for start, end in self.intervals:
            if start > addr:  # Intervals are sorted
                break
            elif start <= addr < end:
                return True
        return False

    @staticmethod
    def find_addr2line() -> Optional[str]:
        addr2line = shutil.which('xtensa-esp32-elf-addr2line')
        if addr2line is None:
            # Fallback to searching folders
            idf_dir = os.path.expanduser('~/.espressif/tools/xtensa-esp32-elf')
            items: List[Tuple[Tuple[int, ...], str]] = []
            for entry in glob.iglob(os.path.join(idf_dir, 'esp-*/xtensa-esp32-elf/bin/xtensa-esp32-elf-addr2line')):
                toolchain_dir = os.path.dirname(entry)  # bin
                toolchain_dir = os.path.dirname(toolchain_dir)  # xtensa-esp32-elf
                toolchain_dir = os.path.dirname(toolchain_dir)  # esp-*
                if (m := VERSION_RE.search(toolchain_dir)) is not None:
                    version = tuple(map(int, m.group().split('.')))
                    items.append((version, entry))
            if len(items) > 0:
                _, addr2line = min(items)
        return addr2line

    ADDR2LINE = find_addr2line()

    def __call__(self, addr: int) -> str | None:
        if addr not in self or self.ADDR2LINE is None:
            return None

        cmd = [self.ADDR2LINE, '-pfiaC', '-e', os.path.realpath(self.elf_path), hex(addr)]
        try:
            output = subprocess.check_output(cmd, shell=False, universal_newlines=True)
            return output.strip() if '?? ??:0' not in output else None
        except OSError:
            pass
        return None


class TTYReader:
    def __init__(self, port: str, elf_path: Optional[str] = None, timeout: float = 0.5):
        self.tty = serial.Serial(port=port, timeout=timeout)
        self.addr_translator = PCAddrTranslator(elf_path)
        self.expect_eof = False
        self.test_result = None

    def convert_addresses(self, line: bytes):
        # Does it have any address in it?
        matches = re.findall(ADDRESS_RE, line.decode(errors='ignore'))
        if len(matches) > 0:
            # Flush so that we see the correct interleave of streams
            sys.stdout.buffer.flush()
        for m in matches:
            try:
                if (trace := self.addr_translator(int(m, 16))) is not None:
                    print(trace, file=sys.stderr)
            except ValueError:
                pass

    @staticmethod
    def detect_abort(buffer: bytes) -> bool:
        return BACKTRACE_RE.search(buffer.decode(errors='ignore')) is not None

    def process_line(self, line: bytes):
        sys.stdout.buffer.write(line)
        self.convert_addresses(line)
        if SUCCESS_RE.search(line.decode(errors='ignore')) is not None:
            self.expect_eof = True
        line_str_noansi = ANSI_RE.sub('', line.decode(errors='ignore'))
        if (m := TEST_RESULT_RE.match(line_str_noansi)) is not None:
            success, total = map(int, map(str.strip, m.group(1).split('|')))
            print(f'GREPME test percentage: {success/total:%}', file=sys.stderr)

    def pulse(self):
        self.tty.setDTR(False)
        time.sleep(0.1)
        self.tty.setDTR(True)

    def _process_buffer(self, buffer: bytes) -> bytes:
        lines = buffer.splitlines(keepends=True)  # type: List[bytes]
        if len(lines) > 0:
            if lines[-1].endswith(b'\n'):
                buffer = b''
            else:
                buffer = lines.pop()
                if TTYReader.detect_abort(buffer):
                    self.expect_eof = True
        if len(lines) > 0:
            for line in lines:
                self.process_line(line)
            sys.stdout.buffer.flush()
        return buffer

    def main(self):
        buffer: bytes = b''
        while True:
            new_data = self.tty.read()
            buffer = self._process_buffer(buffer + new_data)
            if len(new_data) == 0 and self.expect_eof:
                self._process_buffer(buffer + b'\n')
                break


if __name__ == '__main__':
    tty = TTYReader('/dev/ttyACM0', '/home/spak/Development/Mittelab/libspookyaction/build/tests.elf')
    try:
        tty.pulse()
        tty.main()
    except KeyboardInterrupt:
        pass
