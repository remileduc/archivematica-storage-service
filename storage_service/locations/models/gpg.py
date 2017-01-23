from __future__ import absolute_import
# stdlib, alphabetical
import datetime
import gnupg
gpg = gnupg.GPG()
import os

# Core Django, alphabetical
from django.db import models

# Third party dependencies, alphabetical

# This project, alphabetical

# This module, alphabetical
from .location import Location


GPG_KEY_REAL_NAME = 'Archivematica Key'
GPG_KEY_PASSPHRASE = ''


class GPG(models.Model):
    """ Spaces found in the local filesystem of the storage service."""
    space = models.OneToOneField('Space', to_field='uuid')

    class Meta:
        verbose_name = "GPG encryption on Local Filesystem"
        app_label = 'locations'

    ALLOWED_LOCATION_PURPOSE = [
        Location.AIP_STORAGE,
        #Location.DIP_STORAGE,
        #Location.BACKLOG,
    ]

    def move_to_storage_service(self, src_path, dest_path, dest_space):
        """Moves src_path to dest_space.staging_path/dest_path."""
        encrypted_src_path = self._gpg_encrypt_in_situ(src_path)
        self.space.create_local_directory(dest_path)
        return self.space.move_rsync(encrypted_src_path, dest_path)

    def move_from_storage_service(self, source_path, destination_path, package=None):
        """ Moves self.staging_path/src_path to dest_path. """
        self.space.create_local_directory(destination_path)
        # TODO: move_rsync will be looking for a '.gpg'-less path...
        self.space.move_rsync(source_path, destination_path, try_mv_local=True)
        self._gpg_decrypt_in_situ(destination_path)

    def _browse(self, path):
        """At present we are not implementing a ``browse`` method for ``GPG``.
        This means that calls to ``browse`` will be routed to
        ``Space.browse_local``, which may be fine.
        """
        pass

    def _delete_path(self, delete_path):
        """At present we are not implementing a ``delete_path`` method for
        ``GPG``. This means that calls to ``delete_path`` will be routed to
        ``Space._delete_path_local``, which may be fine.
        """
        pass

    def _gpg_encrypt_in_situ(src_path):
        """Use GnuPG to encrypt the file at src_path in situ.

        Questions:

        - Should the unencrypted file at ``src_path`` be destroyed
          post-encryption?
        - How to handle ``src_path`` as directory? Right now raising a general
          Exception
        - If ``src_path`` is HUGE, is ``open(src_path, 'rb')`` inefficient?
        - Use GPG to verify the encryption?

        """
        if os.path.isdir(src_path):
            raise Exception(
                'GPG cannot encrypt a directory. Archive %s first!', src_path)
        key = self._get_key()
        recipients = [key['fingerprint']]
        encr_path = src_path + '.gpg'
        with open(src_path, 'rb') as stream:
            gpg.encrypt_file(
                stream,
                recipients,
                armor=False,
                output=encr_path)
        return encr_path

    def _gpg_decrypt_in_situ(gpg_path):
        """Use GnuPG to decrypt the file at gpg_path in situ."""
        output_path = gpg_path
        if output_path.endswith('.gpg'):
            output_path = output_path[:-4]
        with open(gpg_path, 'rb') as stream:
            decrypted_data = gpg.decrypt_file(
                stream,
                output=output_path)

    def _get_key(self):
        """Check if our example key already exists. If it does, return it.
        If it doesn't, generate it. Returns a Python dict representation of the
        GPG key.
        """
        key = _get_existing_key()
        if key is None:
            # The ``gen_key_input`` method generates a string that GnuPG can
            # parse.
            input_data = gpg.gen_key_input(
                key_type='RSA',
                key_length=4096,
                name_real=GPG_KEY_REAL_NAME,
                passphrase=GPG_KEY_PASSPHRASE
            )
            gpg.gen_key(input_data)
        return _get_existing_key()

    def _get_existing_key():
        """Return the Archivematica public GPG key as a Python dict; if it
        doesn't exist, return ``None``.
        """
        public_keys = gpg.list_keys()
        for key in keys:
            uuids = key['uids']
            for uuid in uuids:
                if uuid.startswith(GPG_KEY_REAL_NAME):
                    return key
        return None

    def verify(self):
        """ Verify that the space is accessible to the storage service. """
        # TODO: Why is this method here? What is its purpose? Investigation
        # shows that the ``NFS`` and ``Fedora`` spaces define and use it while
        # ``LocalFilesystem`` defines it but does not use it.
        # TODO run script to verify that it works
        verified = os.path.isdir(self.space.path)
        self.space.verified = verified
        self.space.last_verified = datetime.datetime.now()
