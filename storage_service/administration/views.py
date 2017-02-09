import subprocess

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm
from django.shortcuts import render, redirect, get_object_or_404
from tastypie.models import ApiKey

from common import utils, gpgutils
from storage_service import __version__ as ss_version
from . import forms as settings_forms


########################## ADMIN ##########################

def settings_edit(request):
    initial_data = utils.get_all_settings()
    common_form = settings_forms.CommonSettingsForm(request.POST or None,
        initial=initial_data, prefix='common')
    default_location_form = settings_forms.DefaultLocationsForm(
        request.POST or None, initial=initial_data, prefix='default_loc')
    if common_form.is_valid() and default_location_form.is_valid():
        # Save settings
        common_form.save()
        default_location_form.save()
        messages.success(request, "Setting saved.")
        return redirect('settings_edit')
    return render(request, 'administration/settings_form.html', locals())


########################## VERSION ########################

def get_git_commit():
    try:
        return subprocess.check_output(['git', 'rev-parse', 'HEAD'])
    except (OSError, subprocess.CalledProcessError):
        return None

def version_view(request):
    return render(request, 'administration/version.html',
        {'version': ss_version,
         'git_commit': get_git_commit()})


########################## USERS ##########################

def user_list(request):
    users = get_user_model().objects.all()
    return render(request, 'administration/user_list.html', locals())

def user_edit(request, id):
    action = "Edit"
    edit_user = get_object_or_404(get_user_model(), id=id)
    user_form = settings_forms.UserChangeForm(request.POST or None, instance=edit_user)
    password_form = SetPasswordForm(data=request.POST or None, user=edit_user)
    if 'user' in request.POST and user_form.is_valid():
        user_form.save()
        messages.success(request, "User information saved.")
        return redirect('user_list')
    elif 'password' in request.POST and password_form.is_valid():
        password_form.save()
        api_key = ApiKey.objects.get(user=edit_user)
        api_key.key = api_key.generate_key()
        api_key.save()
        messages.success(request, "Password changed.")
        return redirect('user_list')
    return render(request, 'administration/user_form.html', locals())

def user_create(request):
    action = "Create"
    user_form = settings_forms.UserCreationForm(request.POST or None)
    if user_form.is_valid():
        user_form.save()
        messages.success(request, "New user {} created.".format(
            user_form.cleaned_data['username']))
        return redirect('user_list')
    return render(request, 'administration/user_form.html', locals())


########################## KEYS ##########################

def key_list(request):
    """List all of the GPG keys that the SS knows about."""
    keys = gpgutils.get_gpg_key_list()
    return render(request, 'administration/key_list.html', locals())

def key_create(request):
    """Create a new key using the POST params; currently these are just the
    real name and email of the key's user/owner.
    """
    action = "Create"
    key_form = settings_forms.KeyCreateForm(request.POST or None)
    if key_form.is_valid():
        cd = key_form.cleaned_data
        key = gpgutils.generate_gpg_key(cd['name_real'], cd['name_email'])
        if key:
            messages.success(request, "New key {} created.".format(
                key.fingerprint))
            return redirect('key_list')
        else:
            messages.warning(
                request,
                "Failed to create key with real name '{}' and email"
                " '{}'.".format(cd['name_real'], cd['name_email']))
    return render(request, 'administration/key_form.html', locals())

def key_import(request):
    """Import an existing key to the storage service by providing its ASCII
    armor in a form field. To get the ASCII armored private key with
    fingerprint ``fingerprint`` via Python GnuPG::

        >>> gpg.export_keys(fingerprint, True)

    From the shell::

        $ gpg --armor --export-secret-keys $FINGERPRINT
    """
    action = "Import"
    key_form = settings_forms.KeyImportForm(request.POST or None)
    if key_form.is_valid():
        cd = key_form.cleaned_data
        fingerprint = gpgutils.import_gpg_key(cd['ascii_armor'])
        if fingerprint:
            messages.success(request, "New key {} created.".format(
                fingerprint))
            return redirect('key_list')
        else:
            messages.warning(
                request,
                "Failed to create key with the supplied ASCII armor")
    return render(request, 'administration/key_form.html', locals())
