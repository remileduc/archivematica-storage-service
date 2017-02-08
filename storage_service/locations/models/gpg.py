from __future__ import absolute_import
# stdlib, alphabetical
import datetime
import logging
from lxml import etree
from lxml.builder import ElementMaker
import os
from uuid import uuid4

# Core Django, alphabetical
from django.db import models
from django.utils import timezone

# Third party dependencies, alphabetical
import gnupg

# This project, alphabetical
from common import utils

# This module, alphabetical
from .location import Location
from .package import Package


LOGGER = logging.getLogger(__name__)


# On a default vagrant/ansible deploy, the .gnupg/ dir will be at
# /var/lib/archivematica/.gnupg/
gpg = gnupg.GPG()
GPG_KEY_REAL_NAME = 'Archivematica Key'
GPG_KEY_PASSPHRASE = ''


class GPGException(Exception):
    pass


class GPG(models.Model):
    """Space for storing things as files encrypted via GnuPG."""

    space = models.OneToOneField('Space', to_field='uuid')

    class Meta:
        verbose_name = "GPG encryption on Local Filesystem"
        app_label = 'locations'

    # Parsed pointer file
    pointer_root = None

    ALLOWED_LOCATION_PURPOSE = [
        Location.AIP_STORAGE
    ]

    def move_to_storage_service(self, src_path, dst_path, dst_space):
        """Moves src_path to dst_path.
        Note: we implicitly assume that the encrypted file in this space has
        the '.gpg' extension. After transport to the storage service, the
        decrypted file will lack this extension.
        """
        LOGGER.debug('GPG ``move_to_storage_service``')
        LOGGER.debug('GPG move_to_storage_service encrypted src_path: %s',
                     src_path)
        LOGGER.debug('GPG move_to_storage_service encrypted dst_path: %s',
                     dst_path)

        #src_path_encr = src_path + '.gpg'
        #dst_path_encr = dst_path + '.gpg'

        self.space.create_local_directory(dst_path)
        self.space.move_rsync(src_path, dst_path)
        #decr_path = self._gpg_decrypt(dst_path)


    def move_from_storage_service(self, src_path, dst_path, package=None):
        """Moves self.staging_path/src_path to dst_path. """
        LOGGER.debug('in move_from_storage_service of GPG')
        LOGGER.debug('GPG move_from, src_path: %s', src_path)
        LOGGER.debug('GPG move_from, dst_path: %s', dst_path)
        if not package:
            raise GPGException('GPG spaces can only contain packages')
        self.space.create_local_directory(dst_path)
        self.space.move_rsync(src_path, dst_path, try_mv_local=True)
        try:
            encr_path = self._gpg_encrypt(dst_path)
        except GPGException:
            # If we fail to encrypt, we move it back. Is this what should be done?
            self.space.move_rsync(dst_path, src_path, try_mv_local=True)
            raise
        self._update_package(package, encr_path)

    def _update_package(self, package, encr_path):
        """
        - update the package with the new current_path
        - update the pointer file ...
        TODO/QUESTION: should this be done here (in the SS) or in a new
        micro-service chain link, e.g., one that occurs after "Store the AIP"?
        """

        # If we update the Package's current_path to the encrypted path here
        # and save it in the db, then package.py::Package.store_aip will update
        # mets:file/mets:FLocat[@xlink:href] appropriately.
        package.current_path = encr_path
        package.save()
        # Update pointer file to contain a record of the encryption.
        # TODO/QUESTION: Allow for AICs too?
        if (    package.pointer_file_path and
                package.package_type in (Package.AIP,)):
            pointer_absolute_path = package.full_pointer_file_path
            root = etree.parse(pointer_absolute_path)
            metsBNS = "{" + utils.NSMAP['mets'] + "}"
            # Add a new <mets:transformFile> under the <mets:file> for the AIP,
            # one which indicates that a decryption transform is needed.
            file_el = root.find('.//mets:file', namespaces=utils.NSMAP)
            if package.uuid in file_el.get('ID', ''):
                # TODO/QUESTION: for compression with 7z using bzip2, the
                # algorithm is "bzip2". Should the algorithm here be "gpg" or
                # "AES256"?
                algorithm = 'gpg'
                # TODO/QUESTION: add a TRANSFORMKEY attr with the id of the GPG
                # private key needed to decrypt this AIP? From METS docs: "A
                # key to be used with the transform algorithm for accessing the
                # file's contents."
                etree.SubElement(file_el, metsBNS + "transformFile",
                    TRANSFORMORDER='1',
                    TRANSFORMTYPE='decryption',
                    TRANSFORMALGORITHM=algorithm)
                # Decompression <transformFile> must have its TRANSFORMORDER
                # attr changed to '2', because decryption is a precondition to
                # decompression.
                decompr_transform_el = file_el.find(
                    'mets:transformFile[@TRANSFORMTYPE="decompression"]',
                    namespaces=utils.NSMAP)
                if decompr_transform_el is not None:
                    decompr_transform_el.set('TRANSFORMORDER', '2')

            # Add a <PREMIS:EVENT> for the encryption event
            # TODO/QUESTION: the pipeline is usually responsible for creating
            # these things in the pointer file. The createPointerFile.py client
            # script, in particular, creates these digiprovMD elements based on
            # events and agents in the pipeline's database. In this case, we are
            # encrypting in the storage service and creating PREMIS events in the
            # pointer file that are *not* also recorded in the database (SS's or
            # AM's). Seems like maybe encryption should occur as a micro-service
            # in the pipeline.
            amdsec = root.find('.//mets:amdSec', namespaces=utils.NSMAP)
            # E = ElementMaker(namespace=utils.NSMAP['mets'], nsmap=utils.NSMAP)
            # etree.SubElement(amdsec
            next_digiprov_md_id = self.get_next_digiprov_md_id(root)
            print('next digiprovMD ID: {}'.format(next_digiprov_md_id))
            digiprovMD = etree.Element(
                metsBNS + 'digiprovMD',
                ID=next_digiprov_md_id)
            mdWrap = etree.SubElement(
                digiprovMD,
                metsBNS + 'mdWrap',
                MDTYPE='PREMIS:EVENT')
            xmlData = etree.SubElement(mdWrap, metsBNS + 'xmlData')
            xmlData.append(self.create_encr_event(root))
            amdsec.append(digiprovMD)

            with open(pointer_absolute_path, 'w') as fileo:
                fileo.write(etree.tostring(root, pretty_print=True))

    def create_encr_event(self, root):
        """Returns a PREMIS Event for the encryption."""
        # The following vars would typically come from an AM Events model.
        encr_event_type = 'encryption'
        encr_event_uuid = str(uuid4())
        encr_event_datetime = timezone.now().isoformat()
        encr_event_detail = escape(
            'program=python-gnupg; version={}'.format(gnupg.__version__))
        premisNS = utils.NSMAP['premis']
        premisBNS = '{' + premisNS + '}'
        xsiNS = utils.NSMAP['xsi']
        xsiBNS = '{' + xsiNS + '}'
        event = etree.Element(
            premisBNS + 'event', nsmap={'premis': premisNS})
        event.set(xsiBNS + 'schemaLocation',
                    premisNS + ' http://www.loc.gov/standards/premis/'
                                'v2/premis-v2-2.xsd')
        event.set('version', '2.2')
        eventIdentifier = etree.SubElement(
            event,
            premisBNS + 'eventIdentifier')
        etree.SubElement(
            eventIdentifier,
            premisBNS + 'eventIdentifierType').text = 'UUID'
        etree.SubElement(
            eventIdentifier,
            premisBNS + 'eventIdentifierValue').text = encr_event_uuid
        etree.SubElement(
            event,
            premisBNS + 'eventType').text = encr_event_type
        etree.SubElement(
            event,
            premisBNS + 'eventDateTime').text = encr_event_datetime
        etree.SubElement(
            event,
            premisBNS + 'eventDetail').text = encr_event_detail
        eventOutcomeInformation = etree.SubElement(
            event,
            premisBNS + 'eventOutcomeInformation')
        etree.SubElement(
            eventOutcomeInformation,
            premisBNS + 'eventOutcome').text = '' # No eventOutcome text at present ...
        eventOutcomeDetail = etree.SubElement(
            eventOutcomeInformation,
            premisBNS + 'eventOutcomeDetail')
        etree.SubElement(
            eventOutcomeDetail,
            premisBNS + 'eventOutcomeDetailNote').text = escape(
                'Yay, GnuPG encryption worked!')
            # Copy the existing <premis:agentIdentifier> data to
            # <premis:linkingAgentIdentifier> elements in our encryption
            # <premis:event>
        for agent_id_el in root.findall(
                './/premis:agentIdentifier', namespaces=utils.NSMAP):
            agent_id_type = agent_id_el.find('premis:agentIdentifierType',
                                                namespaces=utils.NSMAP).text
            agent_id_value = agent_id_el.find('premis:agentIdentifierValue',
                                                namespaces=utils.NSMAP).text
            linkingAgentIdentifier = etree.SubElement(
                event,
                premisBNS + 'linkingAgentIdentifier')
            etree.SubElement(
                linkingAgentIdentifier,
                premisBNS + 'linkingAgentIdentifierType').text = agent_id_type
            etree.SubElement(
                linkingAgentIdentifier,
                premisBNS + 'linkingAgentIdentifierValue').text = agent_id_value
        return event

    def get_next_digiprov_md_id(self, root):
        ids = []
        for digiprov_md_el in root.findall(
                './/mets:digiprovMD', namespaces=utils.NSMAP):
            digiprov_md_id = int(digiprov_md_el.get('ID').replace(
                'digiprovMD_', ''))
            ids.append(digiprov_md_id)
        if ids:
            return 'digiprovMD_{}'.format(max(ids) + 1)
        return 'digiprovMD_1'

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

    def _gpg_encrypt(self, path):
        """Use GnuPG to encrypt the file at ``path`` in situ. Note: we
        add a '.gpg' extension to the encrypted file at ``path``.
        Questions:
        - Should the unencrypted file at ``path`` be destroyed
          post-encryption (as is currently done)?
        - How to handle ``path`` as directory? Currently raising an exception
        """
        LOGGER.debug('Encrypting %s.', path)
        if os.path.isdir(path):
            raise GPGException(
                'GPG cannot encrypt a directory. Archive {} first!'.format(
                    path))
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
            return encr_path
        else:
            LOGGER.debug('Failed to encrypt %s; storing it unencrypted.', path)
            raise GPGException(
                'Something went wrong when attempting to encrypt'
                ' {}'.format(path))

    def _gpg_decrypt(self, path):
        """Use GnuPG to decrypt the file at path in situ.
        Note: this was tested by attempting to perform a partial re-ingest on
        an encrypted AIP. However, it appears that doing so does not trigger
        the calling of ``move_to_storage_service``...
        """
        #encr_path = path + '.gpg'
        LOGGER.debug('Decrypting %s.', path)
        if not os.path.isfile(path):
            LOGGER.error('There is no path at %s to decrypt.', path)
            raise GPGException('Cannot decrypt file at {}; no such'
                            ' file.'.format(path))
        decr_path, _ = os.path.splitext(path)
        with open(path, 'rb') as stream:
            gpg.decrypt_file(stream, output=decr_path)
        if os.path.isfile(decr_path):
            LOGGER.debug('Successfully decrypted %s.', path)
            os.remove(path)
            return decr_path
        else:
            LOGGER.debug('Failed to decrypt %s.', path)
            raise GPGException('Failed to decrypt file at {}'.format(path))

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


# This replaces non-unicode characters with a replacement character,
# and is primarily used for arbitrary strings (e.g. filenames, paths)
# that might not be valid unicode to begin with.
# NOTE: non-DRY from archivematicaCommon/archivematicaFunctions.py
def escape(string):
    if isinstance(string, str):
        string = string.decode('utf-8', errors='replace')
    return string
