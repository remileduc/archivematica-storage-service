from __future__ import absolute_import
# stdlib, alphabetical
import datetime
import gnupg
import os

# Core Django, alphabetical
from django.db import models

# Third party dependencies, alphabetical

# This project, alphabetical

# This module, alphabetical
from .location import Location


class GPG(models.Model):
    """ Spaces found in the local filesystem of the storage service."""
    space = models.OneToOneField('Space', to_field='uuid')

    class Meta:
        verbose_name = "GPG encryption on Local Filesystem"
        app_label = 'locations'

    ALLOWED_LOCATION_PURPOSE = [
        Location.AIP_RECOVERY,
        Location.AIP_STORAGE,
        Location.DIP_STORAGE,
        Location.CURRENTLY_PROCESSING,
        Location.STORAGE_SERVICE_INTERNAL,
        Location.TRANSFER_SOURCE,
        Location.BACKLOG,
    ]

    def create_key_if_not_exists(self):
        gpg = gnupg.GPG()
        key_input_params = { 'name_real': 'Archivematica',
            'name_email': 'admin@istrat.or',
            'expire_date': '2014-04-01',
            'key_type': 'RSA',
            'key_length': 4096,
            'key_usage': '',
            'subkey_type': 'RSA',
            'subkey_length': 4096,
            'subkey_usage': 'encrypt,sign,auth',
            'passphrase': 'sekrit'}
        key_input = gpg.gen_key_input(**key_input_params)
        archivematica_key = gpg.gen_key(key_input)

    def move_to_storage_service(self, src_path, dest_path, dest_space):
        """ Moves src_path to dest_space.staging_path/dest_path. """
        # Archivematica expects the file to still be on disk even after stored
        self.space.create_local_directory(dest_path)
        return self.space.move_rsync(src_path, dest_path)

    def move_from_storage_service(self, source_path, destination_path, package=None):
        """ Moves self.staging_path/src_path to dest_path. """
        self.space.create_local_directory(destination_path)
        return self.space.move_rsync(source_path, destination_path, try_mv_local=True)

    def verify(self):
        """ Verify that the space is accessible to the storage service. """
        # TODO run script to verify that it works
        verified = os.path.isdir(self.space.path)
        self.space.verified = verified
        self.space.last_verified = datetime.datetime.now()
