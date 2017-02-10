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

# This project, alphabetical
from common import utils
from commom import gpgutils

# This module, alphabetical
from .location import Location
from .package import Package


LOGGER = logging.getLogger(__name__)


class GPGException(Exception):
    pass


class GPG(models.Model):
    """Space for storing things as files encrypted via GnuPG.
    When an AIP is moved to a GPG space, it is encrypted with a
    GPG-space-specific GPG public key and that encryption is documented in the
    AIP's pointer file. When the AIP is moved out of a GPG space (e.g., for
    re-ingest, download), it is decrypted. The intended use case is one wherein
    encrypted AIPs may be transfered to other storage locations that are not
    under the control of AM SS.

    Note: this space has does not (currently) implement the ``browse`` or
    ``delete_path`` methods.
    """

    space = models.OneToOneField('Space', to_field='uuid')

    # The ``key`` attribute of a GPG "space" is the fingerprint (string) of an
    # existing GPG private key that this SS has access to. Note that GPG keys
    # are not represented in the SS database. We rely on GPG for fetching and
    # creating them.
    # TODO: the following configuration will trigger Django into creating
    # migrations that freeze deploy-specific GPG fingerprints in the migration,
    # which is undesirable. For now, I've just manually modified the
    # auto-created migration.
    keys = gpgutils.get_gpg_key_list()
    key_choices = [(key['fingerprint'], ', '.join(key['uids']))
                   for key in gpgutils.get_gpg_key_list()]
    system_key = gpgutils.get_default_gpg_key(keys)
    key = models.CharField(
        max_length=256,
        choices=key_choices,
        default=system_key['fingerprint'],
        verbose_name='GnuPG Private Key',
        help_text='The GnuPG private key that will be able to'
                  ' decrypt packages stored in this space.')

    class Meta:
        verbose_name = "GPG encryption on Local Filesystem"
        app_label = 'locations'

    ALLOWED_LOCATION_PURPOSE = [
        Location.AIP_STORAGE
    ]

    def move_to_storage_service(self, src_path, dst_path, dst_space):
        """Moves AIP at GPG space (at path ``src_path``) to SS at path
        ``dst_path`` and decrypts it there.
        """
        LOGGER.debug('GPG ``move_to_storage_service``')
        LOGGER.debug('GPG move_to_storage_service encrypted src_path: %s',
                     src_path)
        LOGGER.debug('GPG move_to_storage_service encrypted dst_path: %s',
                     dst_path)
        self.space.create_local_directory(dst_path)
        self.space.move_rsync(src_path, dst_path)
        decr_path = self._gpg_decrypt(dst_path)

    def move_from_storage_service(self, src_path, dst_path, package=None):
        """Moves AIP in SS at path ``src_path`` to GPG space at ``dst_path``,
        encrypts it using the GPG Space's designated GPG ``key``, and updtes
        the AIP's pointer file accordingly.
        """
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
            # If we fail to encrypt, we send it back where it done came from.
            # TODO/QUESTION: Is this behaviour desirable?
            self.space.move_rsync(dst_path, src_path, try_mv_local=True)
            raise
        self._update_package(package, encr_path)

    def _update_package(self, package, encr_path):
        """Update the package's (AIP's) ``current_path`` in the database as
        well as its pointer file in order to reflect the encryption event it
        has undergone.
        """
        # We update the Package/AIP model's ``current_path`` to the encrypted
        # (.gpg-suffixed) path here and save it in the db; as a consequence,
        # package.py::Package.store_aip will update
        # mets:file/mets:FLocat[@xlink:href] appropriately.
        package.current_path = encr_path
        package.save()
        # Update the pointer file to contain a record of the encryption.
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
                # something else?
                algorithm = 'gpg'
                # TODO/QUESTION: here we add a TRANSFORMKEY attr valuated to
                # the fingerprint of the GPG private key needed to decrypt this
                # AIP. Is this correct? From METS docs: "A key to be used with
                # the transform algorithm for accessing the file's contents."
                etree.SubElement(
                    file_el,
                    metsBNS + "transformFile",
                    TRANSFORMORDER='1',
                    TRANSFORMTYPE='decryption',
                    TRANSFORMALGORITHM=algorithm,
                    TRANSFORMKEY=self.key
                )
                # Decompression <transformFile> must have its TRANSFORMORDER
                # attr changed to '2', because decryption is a precondition to
                # decompression.
                # TODO: does the logic here need to be more sophisticated? How
                # many <mets:transformFile> elements can there be?
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
            # AM's). Just pointint out the discrepancy.
            amdsec = root.find('.//mets:amdSec', namespaces=utils.NSMAP)
            next_digiprov_md_id = self.get_next_digiprov_md_id(root)
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

            # Write the modified pointer file to disk.
            with open(pointer_absolute_path, 'w') as fileo:
                fileo.write(etree.tostring(root, pretty_print=True))

    def create_encr_event(self, root):
        """Returns a PREMIS Event for the encryption."""
        # The following vars would typically come from an AM Events model.
        encr_event_type = 'encryption'
        # Note the UUID is created here with no other record besides the
        # pointer file.
        encr_event_uuid = str(uuid4())
        encr_event_datetime = timezone.now().isoformat()
        # TODO/QUESTION: this is listing the Python GnuPG version. Probably
        # important to also get the system GnuPG version also?
        encr_event_detail = escape(
            'program=python-gnupg; version={}'.format(gnupg.__version__))
        # Maybe these should be defined in utils like they are in the
        # dashboard's namespaces.py...
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
        # TODO: Python GnuPG doesn't give output during encryption. At least, I
        # couldn't easily find it. What should the text of the
        # <eventOutcomeDetailNote> element be here?
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
        """Return the next digiprovMD ID attribute; something like
        ``'digiprovMD_X'``, where X is an int.
        """
        ids = []
        for digiprov_md_el in root.findall(
                './/mets:digiprovMD', namespaces=utils.NSMAP):
            digiprov_md_id = int(digiprov_md_el.get('ID').replace(
                'digiprovMD_', ''))
            ids.append(digiprov_md_id)
        if ids:
            return 'digiprovMD_{}'.format(max(ids) + 1)
        return 'digiprovMD_1'

    def _gpg_encrypt(self, path):
        """Use GnuPG to encrypt the file at ``path`` using this GPG Space's GPG
        key.
        TODO/QUESTIONS:
        - Should the unencrypted file at ``path`` be destroyed
          post-encryption (as is currently done)?
        - How to handle ``path`` as directory? Currently raising an exception
        """
        LOGGER.debug('Encrypting %s.', path)
        if os.path.isdir(path):
            raise GPGException(
                'GPG cannot encrypt a directory. Archive {} first!'.format(
                    path))
        encr_path = gpgutils.gpg_encrypt_file(path, self.key)
        if os.path.isfile(encr_path):
            LOGGER.debug('Successfully encrypted %s at %s', path, encr_path)
            os.remove(path)
            return encr_path
        else:
            LOGGER.debug('Failed to encrypt %s; storing it unencrypted.', path)
            raise GPGException(
                'Something went wrong when attempting to encrypt'
                ' {}'.format(path))

    def _gpg_decrypt(self, path):
        """Use GnuPG to decrypt the file at ``path`` and then delete the
        encrypted file.
        """
        LOGGER.debug('Decrypting %s.', path)
        if not os.path.isfile(path):
            LOGGER.error('There is no path at %s to decrypt.', path)
            raise GPGException('Cannot decrypt file at {}; no such'
                            ' file.'.format(path))
        decr_path, _ = os.path.splitext(path)
        decr_result = gpgutils.gpg_decrypt_file(path, decr_path)
        if decr_result.ok and os.path.isfile(decr_path):
            LOGGER.debug('Successfully decrypted %s.', path)
            os.remove(path)
            return decr_path
        else:
            LOGGER.debug('Failed to decrypt %s. Reason: %s', path,
                         decr_result.status)
            raise GPGException('Failed to decrypt file at {}. Reason:'
                               ' {}'.format(path, decr_result.status))

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
