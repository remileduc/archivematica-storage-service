from __future__ import absolute_import
# stdlib, alphabetical
import datetime
import logging
import os

# Core Django, alphabetical
from django.db import models

# Third party dependencies, alphabetical
import gnupg

# This project, alphabetical

# This module, alphabetical
from .location import Location


LOGGER = logging.getLogger(__name__)


gpg = gnupg.GPG()
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
        LOGGER.debug('in move_to_storage_service of GPG')
        LOGGER.debug('GPG move_to, src_path: %s', src_path)
        LOGGER.debug('GPG move_to, dest_path: %s', dest_path)
        self.space.create_local_directory(dest_path)
        self.space.move_rsync(src_path, dest_path)
        self._gpg_decrypt_in_situ(dest_path)

    def move_from_storage_service(self, source_path, destination_path, package=None):
        """ Moves self.staging_path/source_path to destination_path. """
        LOGGER.debug('in move_from_storage_service of GPG')
        LOGGER.debug('GPG move_from, source_path: %s', source_path)
        LOGGER.debug('GPG move_from, destination_path: %s', destination_path)
        self.space.create_local_directory(destination_path)
        self.space.move_rsync(source_path, destination_path, try_mv_local=True)
        self._gpg_encrypt_in_situ(destination_path)

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

    def _gpg_encrypt_in_situ(self, path):
        """Use GnuPG to encrypt the file at ``path`` in situ. Note: deletes
        unencrypted copy of file at ``path`` after a successful encryption.
        Questions:
        - Should the unencrypted file at ``path`` be destroyed
          post-encryption (as is currently done)?
        - How to handle ``path`` as directory? Right now raising a general
          Exception
        """
        LOGGER.debug('Encrypting %s.', path)
        if os.path.isdir(path):
            raise Exception(
                'GPG cannot encrypt a directory. Archive %s first!', path)
        key = self._get_key()
        recipients = [key['fingerprint']]
        encr_path = path + '.gpg'
        with open(path, 'rb') as stream:
            gpg.encrypt_file(
                stream,
                recipients,
                armor=False,
                output=encr_path)
        if os.path.isfile(encr_path):
            LOGGER.debug('Successfully encrypted %s', path)
            os.remove(path)
            os.rename(encr_path, path)
        else:
            LOGGER.debug('Failed to encrypt %s; storing it unencrypted.', path)

    def _gpg_decrypt_in_situ(self, path):
        """Use GnuPG to decrypt the file at path in situ.
        Note: this was tested by attempting to perform a partial re-ingest on
        an encrypted AIP. However, it appears that doing so does not trigger
        the calling of ``move_to_storage_service``...
        """
        LOGGER.debug('Decrypting %s.', path)
        output_path = path + '.decrypted'
        with open(path, 'rb') as stream:
            decrypted_data = gpg.decrypt_file(
                stream,
                output=output_path)
        if os.path.isfile(output_path):
            LOGGER.debug('Successfully decrypted %s', path)
            os.remove(path)
            os.rename(output_path, path)
        else:
            LOGGER.debug('Failed to decrypt %s.', path)

    def _get_key(self):
        """Check if our example key already exists. If it does, return it.
        If it doesn't, generate it. Returns a Python dict representation of the
        GPG key.
        """
        key = self._get_existing_key()
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
        return self._get_existing_key()

    def _get_existing_key(self):
        """Return the Archivematica public GPG key as a Python dict; if it
        doesn't exist, return ``None``.
        """
        public_keys = gpg.list_keys()
        for key in public_keys:
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
