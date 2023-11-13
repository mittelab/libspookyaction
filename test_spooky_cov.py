if __name__ == '__main__':
    import pytest
    pytest.main()

import os.path
import sys

import pytest
import re
from pytest_embedded_idf import IdfDut
from pytest_embedded_jtag import OpenOcd

LIBSPOOKY_OBJ_FOLDER = 'esp-idf/libspookyaction/CMakeFiles/__idf_libspookyaction.dir'
GCDA_FOLDERS = ('desfire', 'desfire/esp32', 'pn532', 'pn532/esp32')


def test_gcov(dut: IdfDut, openocd: OpenOcd) -> None:
    # create the generated .gcda folder, otherwise would have error: failed to open file.
    # normally this folder would be created via `idf.py build`. but in CI the non-related files would not be preserved
    for gcda_folder in GCDA_FOLDERS:
        os.makedirs(os.path.join(dut.app.binary_path, LIBSPOOKY_OBJ_FOLDER, gcda_folder), exist_ok=True)

    print('here1', file=sys.stderr)
    openocd.write('reset')
    print('here2', file=sys.stderr)

    while True:
        m = dut.expect('.*$', timeout=30)  # type: re.Match
        if m:
            line = m.group(0)
            print(line.decode(errors='ignore'), file=sys.stderr)
            if b'GREPME' in line:
                break

    def dump_coverage(cmd: str) -> None:
        response = openocd.write(cmd)

        expect_lines = [
            'Targets connected.',
            'Targets disconnected.',
        ]

        for line in response.splitlines():
            for expect in expect_lines[:]:
                if expect in line:
                    if expect.endswith('.gcda'):  # check file exists
                        file_path = line.split()[3].strip("'")
                        assert os.path.isfile(file_path)

                    expect_lines.remove(expect)

        assert len(expect_lines) == 0

    # Test two hard-coded dumps
    dump_coverage('esp gcov')
