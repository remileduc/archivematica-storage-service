
from django.forms import ModelForm

from .models import Space, LocalFilesystem, NFS, Location

class SpaceForm(ModelForm):
    class Meta:
        model = Space
        fields = ('access_protocol', 'size', 'path')

class LocalFilesystemForm(ModelForm):
    class Meta:
        model = LocalFilesystem
        fields = ()

class NFSForm(ModelForm):
    class Meta:
        model = NFS
        fields = ('remote_name', 'remote_path', 'version', 'manually_mounted')


# For validation of resources
class LocationForm(ModelForm):
    class Meta:
        model = Location
        fields = ('purpose', 'pipeline', 'relative_path', 'description', 'quota', 'used')
