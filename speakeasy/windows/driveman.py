# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.defs.windows.kernel32 as k32defs


class DriveManager(object):
    """
    Manages the emulation of Windows drives. Currently assumes one volume per drive.
    """
    def __init__(self, config=None):
        super(DriveManager, self).__init__()
        self.drives = config
        self.drive_letters = [drive.get('root_path')[0] for drive in self.drives]

    def walk_drives(self):
        yield from self.drives

    def get_drive(self, root_path='', volume_guid_path=''):
        for drive in self.drives:
            if root_path:
                config_root_path = drive.get('root_path')
                if config_root_path and root_path == config_root_path:
                    return drive
            elif volume_guid_path:
                config_volume_guid_path = drive.get('volume_guid_path')
                if config_volume_guid_path and \
                        config_volume_guid_path == volume_guid_path:
                    return drive

    def get_drive_type(self, root_path):
        if drive := self.get_drive(root_path=root_path):
            config_root_path = drive.get('root_path')
            if config_root_path == root_path:
                config_drive_type = drive.get('drive_type')
                return k32defs.get_define_value(config_drive_type)

        return k32defs.DRIVE_NO_ROOT_DIR






