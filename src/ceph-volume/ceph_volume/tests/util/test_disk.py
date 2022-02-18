import os
import pytest
from mock.mock import patch
from ceph_volume.util import disk


class TestLsblkParser(object):

    def test_parses_whitespace_values(self):
        output = 'NAME="sdaa5" PARTLABEL="ceph data" RM="0" SIZE="10M" RO="0" TYPE="part"'
        result = disk._lsblk_parser(output)
        assert result['PARTLABEL'] == 'ceph data'

    def test_ignores_bogus_pairs(self):
        output = 'NAME="sdaa5" PARTLABEL RM="0" SIZE="10M" RO="0" TYPE="part" MOUNTPOINT=""'
        result = disk._lsblk_parser(output)
        assert result['SIZE'] == '10M'


class TestBlkidParser(object):

    def test_parses_whitespace_values(self):
        output = '''/dev/sdb1: UUID="62416664-cbaf-40bd-9689-10bd337379c3" TYPE="xfs" PART_ENTRY_SCHEME="gpt" PART_ENTRY_NAME="ceph data" PART_ENTRY_UUID="b89c03bc-bf58-4338-a8f8-a2f484852b4f"'''  # noqa
        result = disk._blkid_parser(output)
        assert result['PARTLABEL'] == 'ceph data'

    def test_ignores_unmapped(self):
        output = '''/dev/sdb1: UUID="62416664-cbaf-40bd-9689-10bd337379c3" TYPE="xfs" PART_ENTRY_SCHEME="gpt" PART_ENTRY_NAME="ceph data" PART_ENTRY_UUID="b89c03bc-bf58-4338-a8f8-a2f484852b4f"'''  # noqa
        result = disk._blkid_parser(output)
        assert len(result.keys()) == 4

    def test_translates_to_partuuid(self):
        output = '''/dev/sdb1: UUID="62416664-cbaf-40bd-9689-10bd337379c3" TYPE="xfs" PART_ENTRY_SCHEME="gpt" PART_ENTRY_NAME="ceph data" PART_ENTRY_UUID="b89c03bc-bf58-4338-a8f8-a2f484852b4f"'''  # noqa
        result = disk._blkid_parser(output)
        assert result['PARTUUID'] == 'b89c03bc-bf58-4338-a8f8-a2f484852b4f'


class TestBlkid(object):

    def test_parses_translated(self, stub_call):
        output = '''/dev/sdb1: UUID="62416664-cbaf-40bd-9689-10bd337379c3" TYPE="xfs" PART_ENTRY_SCHEME="gpt" PART_ENTRY_NAME="ceph data" PART_ENTRY_UUID="b89c03bc-bf58-4338-a8f8-a2f484852b4f"'''  # noqa
        stub_call((output.split(), [], 0))
        result = disk.blkid('/dev/sdb1')
        assert result['PARTUUID'] == 'b89c03bc-bf58-4338-a8f8-a2f484852b4f'
        assert result['PARTLABEL'] == 'ceph data'
        assert result['UUID'] == '62416664-cbaf-40bd-9689-10bd337379c3'
        assert result['TYPE'] == 'xfs'

class TestUdevadmProperty(object):

    def test_good_output(self, stub_call):
        output = """ID_MODEL=SK_hynix_SC311_SATA_512GB
ID_PART_TABLE_TYPE=gpt
ID_SERIAL_SHORT=MS83N71801150416A""".split()
        stub_call((output, [], 0))
        result = disk.udevadm_property('dev/sda')
        assert result['ID_MODEL'] == 'SK_hynix_SC311_SATA_512GB'
        assert result['ID_PART_TABLE_TYPE'] == 'gpt'
        assert result['ID_SERIAL_SHORT'] == 'MS83N71801150416A'

    def test_property_filter(self, stub_call):
        output = """ID_MODEL=SK_hynix_SC311_SATA_512GB
ID_PART_TABLE_TYPE=gpt
ID_SERIAL_SHORT=MS83N71801150416A""".split()
        stub_call((output, [], 0))
        result = disk.udevadm_property('dev/sda', ['ID_MODEL',
                                                   'ID_SERIAL_SHORT'])
        assert result['ID_MODEL'] == 'SK_hynix_SC311_SATA_512GB'
        assert 'ID_PART_TABLE_TYPE' not in result

    def test_fail_on_broken_output(self, stub_call):
        output = ["ID_MODEL:SK_hynix_SC311_SATA_512GB"]
        stub_call((output, [], 0))
        with pytest.raises(ValueError):
            disk.udevadm_property('dev/sda')


class TestDeviceFamily(object):

    def test_groups_multiple_devices(self, stub_call):
        out = [
            'NAME="sdaa5" PARLABEL="ceph lockbox"',
            'NAME="sdaa" RO="0"',
            'NAME="sdaa1" PARLABEL="ceph data"',
            'NAME="sdaa2" PARLABEL="ceph journal"',
        ]
        stub_call((out, '', 0))
        result = disk.device_family('sdaa5')
        assert len(result) == 4

    def test_parses_output_correctly(self, stub_call):
        names = ['sdaa', 'sdaa5', 'sdaa1', 'sdaa2']
        out = [
            'NAME="sdaa5" PARLABEL="ceph lockbox"',
            'NAME="sdaa" RO="0"',
            'NAME="sdaa1" PARLABEL="ceph data"',
            'NAME="sdaa2" PARLABEL="ceph journal"',
        ]
        stub_call((out, '', 0))
        result = disk.device_family('sdaa5')
        for parsed in result:
            assert parsed['NAME'] in names


class TestHumanReadableSize(object):

    def test_bytes(self):
        result = disk.human_readable_size(800)
        assert result == '800.00 B'

    def test_kilobytes(self):
        result = disk.human_readable_size(800*1024)
        assert result == '800.00 KB'

    def test_megabytes(self):
        result = disk.human_readable_size(800*1024*1024)
        assert result == '800.00 MB'

    def test_gigabytes(self):
        result = disk.human_readable_size(8.19*1024*1024*1024)
        assert result == '8.19 GB'

    def test_terabytes(self):
        result = disk.human_readable_size(81.2*1024*1024*1024*1024)
        assert result == '81.20 TB'

    def test_petabytes(self):
        result = disk.human_readable_size(9.23*1024*1024*1024*1024*1024)
        assert result == '9.23 PB'

class TestSizeFromHumanReadable(object):

    def test_bytes(self):
        result = disk.size_from_human_readable('2')
        assert result == disk.Size(b=2)

    def test_kilobytes(self):
        result = disk.size_from_human_readable('2 K')
        assert result == disk.Size(kb=2)

    def test_megabytes(self):
        result = disk.size_from_human_readable('2 M')
        assert result == disk.Size(mb=2)

    def test_gigabytes(self):
        result = disk.size_from_human_readable('2 G')
        assert result == disk.Size(gb=2)

    def test_terabytes(self):
        result = disk.size_from_human_readable('2 T')
        assert result == disk.Size(tb=2)

    def test_petabytes(self):
        result = disk.size_from_human_readable('2 P')
        assert result == disk.Size(pb=2)

    def test_case(self):
        result = disk.size_from_human_readable('2 t')
        assert result == disk.Size(tb=2)

    def test_space(self):
        result = disk.size_from_human_readable('2T')
        assert result == disk.Size(tb=2)

    def test_float(self):
        result = disk.size_from_human_readable('2.0')
        assert result == disk.Size(b=2)
        result = disk.size_from_human_readable('2.0T')
        assert result == disk.Size(tb=2)
        result = disk.size_from_human_readable('1.8T')
        assert result == disk.Size(tb=1.8)


class TestSizeParse(object):

    def test_bytes(self):
        result = disk.Size.parse('2')
        assert result == disk.Size(b=2)

    def test_kilobytes(self):
        result = disk.Size.parse('2K')
        assert result == disk.Size(kb=2)

    def test_megabytes(self):
        result = disk.Size.parse('2M')
        assert result == disk.Size(mb=2)

    def test_gigabytes(self):
        result = disk.Size.parse('2G')
        assert result == disk.Size(gb=2)

    def test_terabytes(self):
        result = disk.Size.parse('2T')
        assert result == disk.Size(tb=2)

    def test_petabytes(self):
        result = disk.Size.parse('2P')
        assert result == disk.Size(pb=2)

    def test_tb(self):
        result = disk.Size.parse('2Tb')
        assert result == disk.Size(tb=2)

    def test_case(self):
        result = disk.Size.parse('2t')
        assert result == disk.Size(tb=2)

    def test_space(self):
        result = disk.Size.parse('2T')
        assert result == disk.Size(tb=2)

    def test_float(self):
        result = disk.Size.parse('2.0')
        assert result == disk.Size(b=2)
        result = disk.Size.parse('2.0T')
        assert result == disk.Size(tb=2)
        result = disk.Size.parse('1.8T')
        assert result == disk.Size(tb=1.8)


class TestGetBlockDevsLsblk(object):

    @patch('ceph_volume.process.call')
    def test_return_structure(self, patched_call):
        lsblk_stdout = [
			'/dev/dm-0 /dev/mapper/ceph--8b2684eb--56ff--49e4--8f28--522e04cbd6ab-osd--data--9fc29fbf--3b5b--4066--be10--61042569b5a7 lvm',
			'/dev/vda  /dev/vda                                                                                                       disk',
			'/dev/vda1 /dev/vda1                                                                                                      part',
			'/dev/vdb  /dev/vdb                                                                                                       disk',]
        patched_call.return_value = (lsblk_stdout, '', 0)
        disks = disk.get_block_devs_lsblk()
        assert len(disks) == len(lsblk_stdout)
        assert len(disks[0]) == 3

    @patch('ceph_volume.process.call')
    def test_empty_lsblk(self, patched_call):
        patched_call.return_value = ([], '', 0)
        disks = disk.get_block_devs_lsblk()
        assert len(disks) == 0

    @patch('ceph_volume.process.call')
    def test_raise_on_failure(self, patched_call):
        patched_call.return_value = ([], 'error', 1)
        with pytest.raises(OSError):
            disk.get_block_devs_lsblk()


class TestGetDevices(object):

    def setup_path(self, tmpdir):
        path = os.path.join(str(tmpdir), 'block')
        os.makedirs(path)
        return path

    def test_no_devices_are_found(self, tmpdir, patched_get_block_devs_lsblk):
        patched_get_block_devs_lsblk.return_value = []
        result = disk.get_devices(_sys_block_path=str(tmpdir))
        assert result == {}

    def test_sda_block_is_found(self, tmpdir, patched_get_block_devs_lsblk):
        sda_path = '/dev/sda'
        patched_get_block_devs_lsblk.return_value = [[sda_path, sda_path, 'disk']]
        block_path = self.setup_path(tmpdir)
        os.makedirs(os.path.join(block_path, 'sda'))
        result = disk.get_devices(_sys_block_path=block_path)
        assert len(result.keys()) == 1
        assert result[sda_path]['human_readable_size'] == '0.00 B'
        assert result[sda_path]['model'] == ''
        assert result[sda_path]['partitions'] == {}


    def test_sda_size(self, tmpfile, tmpdir, patched_get_block_devs_lsblk):
        sda_path = '/dev/sda'
        patched_get_block_devs_lsblk.return_value = [[sda_path, sda_path, 'disk']]
        block_path = self.setup_path(tmpdir)
        block_sda_path = os.path.join(block_path, 'sda')
        os.makedirs(block_sda_path)
        tmpfile('size', '1024', directory=block_sda_path)
        result = disk.get_devices(_sys_block_path=block_path)
        assert list(result.keys()) == [sda_path]
        assert result[sda_path]['human_readable_size'] == '512.00 KB'

    def test_sda_sectorsize_fallsback(self, tmpfile, tmpdir, patched_get_block_devs_lsblk):
        # if no sectorsize, it will use queue/hw_sector_size
        sda_path = '/dev/sda'
        patched_get_block_devs_lsblk.return_value = [[sda_path, sda_path, 'disk']]
        block_path = self.setup_path(tmpdir)
        block_sda_path = os.path.join(block_path, 'sda')
        sda_queue_path = os.path.join(block_sda_path, 'queue')
        os.makedirs(block_sda_path)
        os.makedirs(sda_queue_path)
        tmpfile('hw_sector_size', contents='1024', directory=sda_queue_path)
        result = disk.get_devices(_sys_block_path=block_path)
        assert list(result.keys()) == [sda_path]
        assert result[sda_path]['sectorsize'] == '1024'

    def test_sda_sectorsize_from_logical_block(self, tmpfile, tmpdir, patched_get_block_devs_lsblk):
        sda_path = '/dev/sda'
        patched_get_block_devs_lsblk.return_value = [[sda_path, sda_path, 'disk']]
        block_path = self.setup_path(tmpdir)
        block_sda_path = os.path.join(block_path, 'sda')
        sda_queue_path = os.path.join(block_sda_path, 'queue')
        os.makedirs(block_sda_path)
        os.makedirs(sda_queue_path)
        tmpfile('logical_block_size', contents='99', directory=sda_queue_path)
        result = disk.get_devices(_sys_block_path=block_path)
        assert result[sda_path]['sectorsize'] == '99'

    def test_sda_sectorsize_does_not_fallback(self, tmpfile, tmpdir, patched_get_block_devs_lsblk):
        sda_path = '/dev/sda'
        patched_get_block_devs_lsblk.return_value = [[sda_path, sda_path, 'disk']]
        block_path = self.setup_path(tmpdir)
        block_sda_path = os.path.join(block_path, 'sda')
        sda_queue_path = os.path.join(block_sda_path, 'queue')
        os.makedirs(block_sda_path)
        os.makedirs(sda_queue_path)
        tmpfile('logical_block_size', contents='99', directory=sda_queue_path)
        tmpfile('hw_sector_size', contents='1024', directory=sda_queue_path)
        result = disk.get_devices(_sys_block_path=block_path)
        assert result[sda_path]['sectorsize'] == '99'

    def test_is_rotational(self, tmpfile, tmpdir, patched_get_block_devs_lsblk):
        sda_path = '/dev/sda'
        patched_get_block_devs_lsblk.return_value = [[sda_path, sda_path, 'disk']]
        block_path = self.setup_path(tmpdir)
        block_sda_path = os.path.join(block_path, 'sda')
        sda_queue_path = os.path.join(block_sda_path, 'queue')
        os.makedirs(block_sda_path)
        os.makedirs(sda_queue_path)
        tmpfile('rotational', contents='1', directory=sda_queue_path)
        result = disk.get_devices(_sys_block_path=block_path)
        assert result[sda_path]['rotational'] == '1'

    def test_is_ceph_rbd(self, tmpfile, tmpdir, patched_get_block_devs_lsblk):
        rbd_path = '/dev/rbd0'
        patched_get_block_devs_lsblk.return_value = [[rbd_path, rbd_path, 'disk']]
        block_path = self.setup_path(tmpdir)
        block_rbd_path = os.path.join(block_path, 'rbd0')
        os.makedirs(block_rbd_path)
        result = disk.get_devices(_sys_block_path=block_path)
        assert rbd_path not in result


class TestSizeCalculations(object):

    @pytest.mark.parametrize('aliases', [
        ('b', 'bytes'),
        ('kb', 'kilobytes'),
        ('mb', 'megabytes'),
        ('gb', 'gigabytes'),
        ('tb', 'terabytes'),
    ])
    def test_aliases(self, aliases):
        short_alias, long_alias = aliases
        s = disk.Size(b=1)
        short_alias = getattr(s, short_alias)
        long_alias = getattr(s, long_alias)
        assert short_alias == long_alias

    @pytest.mark.parametrize('values', [
        ('b', 857619069665.28),
        ('kb', 837518622.72),
        ('mb', 817889.28),
        ('gb', 798.72),
        ('tb', 0.78),
    ])
    def test_terabytes(self, values):
        # regardless of the input value, all the other values correlate to each
        # other the same, every time
        unit, value = values
        s = disk.Size(**{unit: value})
        assert s.b == 857619069665.28
        assert s.kb == 837518622.72
        assert s.mb == 817889.28
        assert s.gb == 798.72
        assert s.tb == 0.78


class TestSizeOperators(object):

    @pytest.mark.parametrize('larger', [1025, 1024.1, 1024.001])
    def test_gigabytes_is_smaller(self, larger):
        assert disk.Size(gb=1) < disk.Size(mb=larger)

    @pytest.mark.parametrize('smaller', [1023, 1023.9, 1023.001])
    def test_gigabytes_is_larger(self, smaller):
        assert disk.Size(gb=1) > disk.Size(mb=smaller)

    @pytest.mark.parametrize('larger', [1025, 1024.1, 1024.001, 1024])
    def test_gigabytes_is_smaller_or_equal(self, larger):
        assert disk.Size(gb=1) <= disk.Size(mb=larger)

    @pytest.mark.parametrize('smaller', [1023, 1023.9, 1023.001, 1024])
    def test_gigabytes_is_larger_or_equal(self, smaller):
        assert disk.Size(gb=1) >= disk.Size(mb=smaller)

    @pytest.mark.parametrize('values', [
        ('b', 857619069665.28),
        ('kb', 837518622.72),
        ('mb', 817889.28),
        ('gb', 798.72),
        ('tb', 0.78),
    ])
    def test_equality(self, values):
        unit, value = values
        s = disk.Size(**{unit: value})
        # both tb and b, since b is always calculated regardless, and is useful
        # when testing tb
        assert disk.Size(tb=0.78) == s
        assert disk.Size(b=857619069665.28) == s

    @pytest.mark.parametrize('values', [
        ('b', 857619069665.28),
        ('kb', 837518622.72),
        ('mb', 817889.28),
        ('gb', 798.72),
        ('tb', 0.78),
    ])
    def test_inequality(self, values):
        unit, value = values
        s = disk.Size(**{unit: value})
        # both tb and b, since b is always calculated regardless, and is useful
        # when testing tb
        assert disk.Size(tb=1) != s
        assert disk.Size(b=100) != s


class TestSizeOperations(object):

    def test_assignment_addition_with_size_objects(self):
        result = disk.Size(mb=256) + disk.Size(gb=1)
        assert result.gb == 1.25
        assert result.gb.as_int() == 1
        assert result.gb.as_float() == 1.25

    def test_self_addition_with_size_objects(self):
        base = disk.Size(mb=256)
        base += disk.Size(gb=1)
        assert base.gb == 1.25

    def test_self_addition_does_not_alter_state(self):
        base = disk.Size(mb=256)
        base + disk.Size(gb=1)
        assert base.mb == 256

    def test_addition_with_non_size_objects(self):
        with pytest.raises(TypeError):
            disk.Size(mb=100) + 4

    def test_assignment_subtraction_with_size_objects(self):
        base = disk.Size(gb=1)
        base -= disk.Size(mb=256)
        assert base.mb == 768

    def test_self_subtraction_does_not_alter_state(self):
        base = disk.Size(gb=1)
        base - disk.Size(mb=256)
        assert base.gb == 1

    def test_subtraction_with_size_objects(self):
        result = disk.Size(gb=1) - disk.Size(mb=256)
        assert result.mb == 768

    def test_subtraction_with_non_size_objects(self):
        with pytest.raises(TypeError):
            disk.Size(mb=100) - 4

    def test_multiplication_with_size_objects(self):
        with pytest.raises(TypeError):
            disk.Size(mb=100) * disk.Size(mb=1)

    def test_multiplication_with_non_size_objects(self):
        base = disk.Size(gb=1)
        result = base * 2
        assert result.gb == 2
        assert result.gb.as_int() == 2

    def test_division_with_size_objects(self):
        result = disk.Size(gb=1) / disk.Size(mb=1)
        assert int(result) == 1024

    def test_division_with_non_size_objects(self):
        base = disk.Size(gb=1)
        result = base / 2
        assert result.mb == 512
        assert result.mb.as_int() == 512

    def test_division_with_non_size_objects_without_state(self):
        base = disk.Size(gb=1)
        base / 2
        assert base.gb == 1
        assert base.gb.as_int() == 1


class TestSizeAttributes(object):

    def test_attribute_does_not_exist(self):
        with pytest.raises(AttributeError):
            disk.Size(mb=1).exabytes


class TestSizeFormatting(object):

    def test_default_formatting_tb_to_b(self):
        size = disk.Size(tb=0.0000000001)
        result = "%s" % size
        assert result == "109.95 B"

    def test_default_formatting_tb_to_kb(self):
        size = disk.Size(tb=0.00000001)
        result = "%s" % size
        assert result == "10.74 KB"

    def test_default_formatting_tb_to_mb(self):
        size = disk.Size(tb=0.000001)
        result = "%s" % size
        assert result == "1.05 MB"

    def test_default_formatting_tb_to_gb(self):
        size = disk.Size(tb=0.001)
        result = "%s" % size
        assert result == "1.02 GB"

    def test_default_formatting_tb_to_tb(self):
        size = disk.Size(tb=10)
        result = "%s" % size
        assert result == "10.00 TB"


class TestSizeSpecificFormatting(object):

    def test_formatting_b(self):
        size = disk.Size(b=2048)
        result = "%s" % size.b
        assert "%s" % size.b == "%s" % size.bytes
        assert result == "2048.00 B"

    def test_formatting_kb(self):
        size = disk.Size(kb=5700)
        result = "%s" % size.kb
        assert "%s" % size.kb == "%s" % size.kilobytes
        assert result == "5700.00 KB"

    def test_formatting_mb(self):
        size = disk.Size(mb=4000)
        result = "%s" % size.mb
        assert "%s" % size.mb == "%s" % size.megabytes
        assert result == "4000.00 MB"

    def test_formatting_gb(self):
        size = disk.Size(gb=77777)
        result = "%s" % size.gb
        assert "%s" % size.gb == "%s" % size.gigabytes
        assert result == "77777.00 GB"

    def test_formatting_tb(self):
        size = disk.Size(tb=1027)
        result = "%s" % size.tb
        assert "%s" % size.tb == "%s" % size.terabytes
        assert result == "1027.00 TB"
