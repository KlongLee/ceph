import yaml

from ceph.deployment.inventory import Device
from ceph.deployment.service_spec import ServiceSpec, PlacementSpec
from ceph.deployment.hostspec import SpecValidationError

try:
    from typing import Optional, List, Dict, Any, Union
except ImportError:
    pass


class DeviceSelection(object):
    """
    Used within :class:`ceph.deployment.drive_group.DriveGroupSpec` to specify the devices
    used by the Drive Group.

    Any attributes (even none) can be included in the device
    specification structure.
    """

    _supported_filters = [
            "paths", "size", "vendor", "model", "rotational", "limit", "all"
    ]

    def __init__(self,
                 paths=None,  # type: Optional[List[str]]
                 model=None,  # type: Optional[str]
                 size=None,  # type: Optional[str]
                 rotational=None,  # type: Optional[bool]
                 limit=None,  # type: Optional[int]
                 vendor=None,  # type: Optional[str]
                 all=False,  # type: bool
                 ):
        """
        ephemeral drive group device specification
        """
        #: List of Device objects for devices paths.
        self.paths = [] if paths is None else [Device(path) for path in paths]  # type: List[Device]

        #: A wildcard string. e.g: "SDD*" or "SanDisk SD8SN8U5"
        self.model = model

        #: Match on the VENDOR property of the drive
        self.vendor = vendor

        #: Size specification of format LOW:HIGH.
        #: Can also take the the form :HIGH, LOW:
        #: or an exact value (as ceph-volume inventory reports)
        self.size:  Optional[str] = size

        #: is the drive rotating or not
        self.rotational = rotational

        #: Limit the number of devices added to this Drive Group. Devices
        #: are used from top to bottom in the output of ``ceph-volume inventory``
        self.limit = limit

        #: Matches all devices. Can only be used for data devices
        self.all = all

    def validate(self, name: str) -> None:
        props = [self.model, self.vendor, self.size, self.rotational]  # type: List[Any]
        if self.paths and any(p is not None for p in props):
            raise DriveGroupValidationError(
                name,
                'device selection: `paths` and other parameters are mutually exclusive')
        is_empty = not any(p is not None and p != [] for p in [self.paths] + props)
        if not self.all and is_empty:
            raise DriveGroupValidationError(name, 'device selection cannot be empty')

        if self.all and not is_empty:
            raise DriveGroupValidationError(
                name,
                'device selection: `all` and other parameters are mutually exclusive. {}'.format(
                    repr(self)))

    @classmethod
    def from_json(cls, device_spec):
        # type: (dict) -> Optional[DeviceSelection]
        if not device_spec:
            return None
        for applied_filter in list(device_spec.keys()):
            if applied_filter not in cls._supported_filters:
                raise KeyError(applied_filter)

        return cls(**device_spec)

    def to_json(self):
        # type: () -> Dict[str, Any]
        ret: Dict[str, Any] = {}
        if self.paths:
            ret['paths'] = [p.path for p in self.paths]
        if self.model:
            ret['model'] = self.model
        if self.vendor:
            ret['vendor'] = self.vendor
        if self.size:
            ret['size'] = self.size
        if self.rotational is not None:
            ret['rotational'] = self.rotational
        if self.limit:
            ret['limit'] = self.limit
        if self.all:
            ret['all'] = self.all

        return ret

    def __repr__(self) -> str:
        keys = [
            key for key in self._supported_filters + ['limit'] if getattr(self, key) is not None
        ]
        if 'paths' in keys and self.paths == []:
            keys.remove('paths')
        return "DeviceSelection({})".format(
            ', '.join('{}={}'.format(key, repr(getattr(self, key))) for key in keys)
        )

    def __eq__(self, other: Any) -> bool:
        return repr(self) == repr(other)


class DriveGroupValidationError(SpecValidationError):
    """
    Defining an exception here is a bit problematic, cause you cannot properly catch it,
    if it was raised in a different mgr module.
    """

    def __init__(self, name: str, msg: str):
        super(DriveGroupValidationError, self).__init__(
            f'Failed to validate OSD spec "{name}": {msg}')


class DriveGroupSpec(ServiceSpec):
    """
    Describe a drive group in the same form that ceph-volume
    understands.
    """

    _supported_features = [
        "encrypted", "block_wal_size", "osds_per_device",
        "db_slots", "wal_slots", "block_db_size", "placement", "service_id", "service_type",
        "data_devices", "db_devices", "wal_devices", "journal_devices",
        "data_directories", "osds_per_device", "objectstore", "osd_id_claims",
        "journal_size", "unmanaged", "filter_logic", "preview_only"
    ]

    def __init__(self,
                 placement=None,  # type: Optional[PlacementSpec]
                 service_id=None,  # type: Optional[str]
                 data_devices=None,  # type: Optional[DeviceSelection]
                 db_devices=None,  # type: Optional[DeviceSelection]
                 wal_devices=None,  # type: Optional[DeviceSelection]
                 journal_devices=None,  # type: Optional[DeviceSelection]
                 data_directories=None,  # type: Optional[List[str]]
                 osds_per_device=None,  # type: Optional[int]
                 objectstore='bluestore',  # type: str
                 encrypted=False,  # type: bool
                 db_slots=None,  # type: Optional[int]
                 wal_slots=None,  # type: Optional[int]
                 osd_id_claims=None,  # type: Optional[Dict[str, List[str]]]
                 block_db_size=None,  # type: Union[int, str, None]
                 block_wal_size=None,  # type: Union[int, str, None]
                 journal_size=None,  # type: Union[int, str, None]
                 service_type=None,  # type: Optional[str]
                 unmanaged=False,  # type: bool
                 filter_logic='AND',  # type: str
                 preview_only=False,  # type: bool
                 ):
        assert service_type is None or service_type == 'osd'
        super(DriveGroupSpec, self).__init__('osd', service_id=service_id,
                                             placement=placement,
                                             unmanaged=unmanaged,
                                             preview_only=preview_only)

        #: A :class:`ceph.deployment.drive_group.DeviceSelection`
        self.data_devices = data_devices

        #: A :class:`ceph.deployment.drive_group.DeviceSelection`
        self.db_devices = db_devices

        #: A :class:`ceph.deployment.drive_group.DeviceSelection`
        self.wal_devices = wal_devices

        #: A :class:`ceph.deployment.drive_group.DeviceSelection`
        self.journal_devices = journal_devices

        #: Set (or override) the "bluestore_block_wal_size" value, in bytes
        self.block_wal_size: Union[int, str, None] = block_wal_size

        #: Set (or override) the "bluestore_block_db_size" value, in bytes
        self.block_db_size: Union[int, str, None] = block_db_size

        #: set journal_size in bytes
        self.journal_size: Union[int, str, None] = journal_size

        #: Number of osd daemons per "DATA" device.
        #: To fully utilize nvme devices multiple osds are required.
        self.osds_per_device = osds_per_device

        #: A list of strings, containing paths which should back OSDs
        self.data_directories = data_directories

        #: ``filestore`` or ``bluestore``
        self.objectstore = objectstore

        #: ``true`` or ``false``
        self.encrypted = encrypted

        #: How many OSDs per DB device
        self.db_slots = db_slots

        #: How many OSDs per WAL device
        self.wal_slots = wal_slots

        #: Optional: mapping of host -> List of osd_ids that should be replaced
        #: See :ref:`orchestrator-osd-replace`
        self.osd_id_claims = osd_id_claims or dict()

        #: The logic gate we use to match disks with filters.
        #: defaults to 'AND'
        self.filter_logic = filter_logic.upper()

        #: If this should be treated as a 'preview' spec
        self.preview_only = preview_only

    @classmethod
    def _from_json_impl(cls, json_drive_group):
        # type: (dict) -> DriveGroupSpec
        """
        Initialize 'Drive group' structure

        :param json_drive_group: A valid json string with a Drive Group
               specification
        """
        args: Dict[str, Any] = {}
        # legacy json (pre Octopus)
        if 'host_pattern' in json_drive_group and 'placement' not in json_drive_group:
            json_drive_group['placement'] = {'host_pattern': json_drive_group['host_pattern']}
            del json_drive_group['host_pattern']

        args['service_type'] = json_drive_group.pop('service_type', 'osd')

        # service_id was not required in early octopus.
        args['service_id'] = json_drive_group.pop('service_id', '')
        s_id = args['service_id']
        try:
            args['placement'] = PlacementSpec.from_json(json_drive_group.pop('placement'))
        except KeyError:
            args['placement'] = PlacementSpec()

        # spec: was not mandatory in octopus
        if 'spec' in json_drive_group:
            args.update(cls._drive_group_spec_from_json(s_id, json_drive_group.pop('spec')))
        else:
            args.update(cls._drive_group_spec_from_json(s_id, json_drive_group))

        args['unmanaged'] = json_drive_group.pop('unmanaged', False)

        return cls(**args)

    @classmethod
    def _drive_group_spec_from_json(cls, name: str, json_drive_group: dict) -> dict:
        for applied_filter in list(json_drive_group.keys()):
            if applied_filter not in cls._supported_features:
                raise DriveGroupValidationError(
                    name,
                    "Feature `{}` is not supported".format(applied_filter))

        try:
            def to_selection(key: str, vals: dict) -> Optional[DeviceSelection]:
                try:
                    return DeviceSelection.from_json(vals)
                except KeyError as e:
                    raise DriveGroupValidationError(
                        f'{name}.{key}',
                        f"Filtering for `{e.args[0]}` is not supported")

            args = {k: (to_selection(k, v) if k.endswith('_devices') else v) for k, v in
                    json_drive_group.items()}
            if not args:
                raise DriveGroupValidationError(name, "Didn't find drive selections")
            return args
        except (KeyError, TypeError) as e:
            raise DriveGroupValidationError(name, str(e))

    def validate(self):
        # type: () -> None
        super(DriveGroupSpec, self).validate()

        if not self.service_id:
            raise DriveGroupValidationError('', 'service_id is required')

        if not isinstance(self.placement.host_pattern, str) and \
                self.placement.host_pattern is not None:
            raise DriveGroupValidationError(self.service_id, 'host_pattern must be of type string')

        if self.data_devices is None:
            raise DriveGroupValidationError(self.service_id, "`data_devices` element is required.")

        specs_names = "data_devices db_devices wal_devices journal_devices".split()
        specs = dict(zip(specs_names, [getattr(self, k) for k in specs_names]))
        for k, s in [ks for ks in specs.items() if ks[1] is not None]:
            assert s is not None
            s.validate(f'{self.service_id}.{k}')
        for s in filter(None, [self.db_devices, self.wal_devices, self.journal_devices]):
            if s.all:
                raise DriveGroupValidationError(
                    self.service_id,
                    "`all` is only allowed for data_devices")

        if self.objectstore not in ('bluestore'):
            raise DriveGroupValidationError(self.service_id,
                                            f"{self.objectstore} is not supported. Must be "
                                            f"one of ('bluestore')")

        if self.block_wal_size is not None and type(self.block_wal_size) not in [int, str]:
            raise DriveGroupValidationError(
                self.service_id,
                'block_wal_size must be of type int or string')
        if self.block_db_size is not None and type(self.block_db_size) not in [int, str]:
            raise DriveGroupValidationError(
                self.service_id,
                'block_db_size must be of type int or string')
        if self.journal_size is not None and type(self.journal_size) not in [int, str]:
            raise DriveGroupValidationError(
                self.service_id,
                'journal_size must be of type int or string')

        if self.filter_logic not in ['AND', 'OR']:
            raise DriveGroupValidationError(
                self.service_id,
                'filter_logic must be either <AND> or <OR>')


yaml.add_representer(DriveGroupSpec, DriveGroupSpec.yaml_representer)
