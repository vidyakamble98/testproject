#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = r'''
---
module: keepass
short_description: This a module to interact with a keepass (kdbx) database.
version_added: '2.9'
description:
    - This a module to interact with a keepass (kdbx) database.
requirements:
    - PyKeePass
options:
    keepass_database:
        description:
            - Path of the keepass database.
        required: true
        type: str
    keepass_password:
        description:
            - Password for the kdbx. Either this or 'keepass_keyfile' (or both) are required.
        required: false
        type: str
    keepass_keyfile:
        description:
            - Path of the keepass keyfile. Either this or 'keepass_password' (or both) are required.
        required: false
        type: str
    state:
        description:
            - State of this entry, either present (default) or absent.
        required: false
        type: str
    entry_title:
        description:
            - Title of the entry.
        required: true
        type: str
    entry_username:
        description:
            - Username of the entry.
        required: true
        type: str
    entry_group:
        description:
            - The name of the group where the entry should be. Defaults to root_group, ie: slash.
        required: false
        type: str
    entry_group_recursive:
        description:
            - If false, search for entry is done on strict group. If True, search is done from given path, including subdirectories.
        required: false
        type: bool
    entry_password:
        description:
            - Password of the entry.
        required: false
        type: str
    search_regex:
        description:
            - Boolean to know if given title and username are in fact regex.
        required: false
        type: bool
    search_flags:
        description:
            - Flag for regex, only use is to put 'i' for insensitive case.
        required: false
        type: str
    search_key:
        description:
            - Possible values are default 'title,username' or 'title'. Search for etry is done with title+username, or only title.
        required: false
        type: str
author:
    - Linuxfabrik GmbH, Zurich, Switzerland
    - Tommy STYCZEN

'''

EXAMPLES = r'''
- name: Create entry
  keepass:
        keepass_database: /etc/ansible/SpringPortal.kdbx
        keepass_password: 2017SpringHPPortal!!
        entry_title: dbhost01.localdomain
        entry_username: mariadb-admin
        entry_password: myPassw0rd
        entry_group: UNIX/AIX/SERVEUR
  register: creds
- debug:
        msg: "Username: {{ creds.username }}, Password: {{ creds.password }}, New password: {{ creds.changed }}"

- name: Update entry with strong password
  keepass:
        keepass_database: /etc/ansible/SpringPortal.kdbx
        keepass_password: 2017SpringHPPortal!!
        entry_title: dbhost01.localdomain
        entry_username: mariadb-admin
        entry_password: mYsTr0nGP@ass!
        entry_group: UNIX/AIX/SERVEUR
  register: creds
- debug:
        msg: "Username: {{ creds.username }}, Password: {{ creds.password }}, New password: {{ creds.changed }}"

- name: Get entry with regex, case insensitive and recursive group
  keepass:
        keepass_database: /etc/ansible/SpringPortal.kdbx
        keepass_password: 2017SpringHPPortal!!
        entry_title: .*DBHOST01.*
        entry_username: none
        entry_group: UNIX
        entry_group_recursive: true
        search_regex: true
        search_flags: i
        search_key: title
  register: creds
- debug:
        msg: "Title: {{ creds.title }}, Username: {{ creds.username }}, Password: {{ creds.password }}, URL: {{ creds.url }}"

- name: Create entry in new group with existing subroot
  keepass:
        keepass_database: /etc/ansible/SpringPortal.kdbx
        keepass_password: 2017SpringHPPortal!!
        entry_title: dbhost02.localdomain
        entry_username: admin
        entry_password: myPassw0rd2
        entry_group: UNIX/BSD/SERVEUR
  register: creds
- debug:
        msg: "Username: {{ creds.username }}, Password: {{ creds.password }}, New password: {{ creds.changed }}"

- name: Create entry in new group without existing subroot
  keepass:
        keepass_database: /etc/ansible/SpringPortal.kdbx
        keepass_password: 2017SpringHPPortal!!
        entry_title: dbhost03.localdomain
        entry_username: yolo
        entry_password: myPassw0rd3
        entry_group: OTHER/PATH/SERV
  register: creds
- debug:
        msg: "Username: {{ creds.username }}, Password: {{ creds.password }}, New password: {{ creds.changed }}"

- name: Create entry in new group without existing subroot but existing group elsewhere
  keepass:
        keepass_database: /etc/ansible/SpringPortal.kdbx
        keepass_password: 2017SpringHPPortal!!
        entry_title: dbhost04.localdomain
        entry_username: root
        entry_password: myPassw0rd4
        entry_group: SERVEUR
  register: creds
- debug:
        msg: "Username: {{ creds.username }}, Password: {{ creds.password }}, New password: {{ creds.changed }}"

- name: Delete non-existing entry
  keepass:
        keepass_database: /etc/ansible/SpringPortal.kdbx
        keepass_password: 2017SpringHPPortal!!
        entry_title: dbhost01.localdomain
        entry_username: mariadb-admin
        state: absent
        entry_group: UNIX/LINUX/SERVEUR

- name: Delete existing entry
  keepass:
        keepass_database: /etc/ansible/SpringPortal.kdbx
        keepass_password: 2017SpringHPPortal!!
        entry_title: dbhost01.localdomain
        entry_username: mariadb-admin
        state: absent
        entry_group: UNIX/AIX/SERVEUR

'''

RETURN = r'''
title:
    description: Title of entry
    type: str
username:
    description: Username of entry
    type: str
password:
    description: The generated or retrieved password
    type: str
group:
    description: Group name of entry
    type: str
url:
    description: URL of entry
    type: str
notes:
    description: Notes of entry
    type: str

'''
import traceback
import subprocess
import argparse

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

PYKEEPASS_IMP_ERR = None
try:
    from pykeepass import PyKeePass
    from pykeepass.exceptions import CredentialsError
except ImportError:
    PYKEEPASS_IMP_ERR = traceback.format_exc()
    pykeepass_found = False
else:
    pykeepass_found = True

def main():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        keepass_database=dict(type='str', required=True),
        keepass_keyfile=dict(type='str', required=False, default=None),
        keepass_password=dict(type='str', required=False, default=None, no_log=True),
        state=dict(type='str', required=False, default='present'),
        entry_title=dict(type='str', required=True),
        entry_username=dict(type='str', required=True),
        entry_group=dict(type='str', required=False, default='/'),
        entry_group_recursive=dict(type='bool', required=False, default=False),
        entry_password=dict(type='str', required=False, no_log=True),
        search_regex=dict(type='bool', required=False, default=False),
        search_flags=dict(type='str', required=False, default=None),
        search_key=dict(type='str', required=False, default='title,username'),
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # change is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        title='',
        username='',
        password='',
        group="",
        url='',
        notes=''
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if not pykeepass_found:
        module.fail_json(msg=missing_required_lib("pykeepass"), exception=PYKEEPASS_IMP_ERR)

    keepass_database      = module.params['keepass_database']
    keepass_keyfile       = module.params['keepass_keyfile']
    keepass_password      = module.params['keepass_password']
    state                 = module.params['state']
    entry_title           = module.params['entry_title']
    entry_username        = module.params['entry_username']
    entry_group           = module.params['entry_group']
    entry_group_recursive = module.params['entry_group_recursive']
    entry_password        = module.params['entry_password']
    search_regex          = module.params['search_regex']
    search_flags          = module.params['search_flags']
    search_key            = module.params['search_key']


    if not keepass_password and not keepass_keyfile:
        module.fail_json(msg="Either 'password' or 'keyfile' (or both) are required.")

    # open keepass database
    try:
        kp = PyKeePass(keepass_database, password=keepass_password, keyfile=keepass_keyfile)
        if entry_group == '/':
            kgroup=kp.root_group
            entry_group=kgroup.name
        else:
            if "/" not in entry_group:
                kgroup = kp.find_groups(path=entry_group.split(), regex=True)
            else:
                kgroup = kp.find_groups(path=entry_group.split('/'), regex=True)
    except IOError as e:
        KEEPASS_OPEN_ERR = traceback.format_exc()
        module.fail_json(msg='Could not open the database or keyfile.')
    except CredentialsError as e:
        KEEPASS_OPEN_ERR = traceback.format_exc()
        module.fail_json(msg='Could not open the database. Credentials are wrong or integrity check failed')

    if not module.check_mode:
        #if we need to create new group
        try:
            kgroup.name
        except AttributeError as e:
            if "/" not in entry_group:
                kgroup = kp.add_group(kp.root_group, entry_group)
            else:
                #testing where we need to add subgroups
                kgroup=None
                for i in range(len(entry_group.split("/"))-1):
                    r_group= entry_group.rsplit("/",i+1)
                    k_find = kp.find_groups(path=r_group[0].split(), regex=True)
                    if k_find is not None:
                        #we found root, we need to create groups in rsplit
                        kgroup_prev=k_find
                        for j in range(len(r_group)-1):
                            kgroup_new = kp.add_group(kgroup_prev, r_group[j+1])
                            kgroup_prev = kgroup_new
                        kgroup = kp.find_groups(path=entry_group.split('/'), regex=True)
                        break;

                if kgroup is None:
                    #need to create entire path
                    kgroup_prev=kp.root_group
                    for subg in entry_group.rsplit("/"):
                        kgroup_new = kp.add_group(kgroup_prev, subg)
                        kgroup_prev = kgroup_new
                    kgroup = kp.find_groups(path=entry_group.split('/'), regex=True)

    # [DELETE] state absent: delete entry
    if state == 'absent':
        if not module.check_mode:
            # check if entry exists
            entry_to_delete = kp.find_entries(title=entry_title, username=entry_username, group=kgroup, recursive=False, first=True)
            if entry_to_delete:
                try:
                    deleteEntry(module, kp, entry_to_delete)
                    result['changed'] = True
                except:
                    KEEPASS_SAVE_ERR = traceback.format_exc()
                    module.fail_json(msg='Could not delete the entry or save the database.', exception=KEEPASS_SAVE_ERR)
        else:
            result['changed'] = True

        module.exit_json(**result)

    # state present: create or modify if exists
    else:
        # check if entry exists
        entry = kp.find_entries(title=entry_title, username=entry_username, group=kgroup, regex=search_regex, flags=search_flags, recursive=entry_group_recursive, first=not(entry_group_recursive))
        if search_key == 'title':
            entry = kp.find_entries(title=entry_title, group=kgroup, regex=search_regex, flags=search_flags, recursive=entry_group_recursive, first=not(entry_group_recursive))
        if entry:
            if (entry_group_recursive and len(entry) > 1):
                module.fail_json(msg='Multiples entries found in group(s).')
            else:
                if (entry_group_recursive):
                    entry = entry[0];
                # [UPDATE] if entry_password defined, modify password
                if entry_password:
                    try:
                        if not module.check_mode:
                            modifyPassword(module, kp, entry, entry_password)
                        result['title'] = entry.title
                        result['username'] = entry.username
                        result['password'] = entry_password
                        result['url'] = entry.url
                        result['notes'] = entry.notes
                        result['group'] = "/".join(map(str, entry.group.path))
                        result['changed'] = True
                    except:
                        KEEPASS_SAVE_ERR = traceback.format_exc()
                        module.fail_json(msg='Could not modify the entry or save the database.', exception=KEEPASS_SAVE_ERR)
                    module.exit_json(**result)
                # [GET] if entry_password NOT defined, just return username and password for associated entry
                else:
                    result['title'] = entry.title
                    result['username'] = entry.username
                    result['password'] = entry.password
                    result['url'] = entry.url
                    result['notes'] = entry.notes
                    result['group'] = "/".join(map(str, entry.group.path))
                    module.exit_json(**result)

        if not module.check_mode:
            # [CREATE] if there is no matching entry, create a new one
            if entry_password:
                try:
                    entry = createEntry(module, kp, entry_title.replace("^","").replace("$",""), entry_username.replace("^","").replace("$",""), kgroup, entry_password)
                    result['title'] = entry.title.replace("^","").replace("$","")
                    result['username'] = entry.username.replace("^","").replace("$","")
                    result['password'] = entry.password
                    result['group'] = "/".join(map(str, entry.group.path))
                    result['changed'] = True
                except:
                    KEEPASS_SAVE_ERR = traceback.format_exc()
                    module.fail_json(msg='Could not add the entry or save the database.', exception=KEEPASS_SAVE_ERR)
            else:
                module.fail_json(msg='Could not find the entry.')
        else:
            result['title'] = entry_title.replace("^","").replace("$","")
            result['username'] = entry_username.replace("^","").replace("$","")
            result['password'] = entry_password
            result['group'] = entry_group
            result['changed'] = True

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def generatePassword(module, length):
    import string
    alphabet = string.ascii_letters + string.digits
    try:
        import secrets as random
    except ImportError:
        import random

    password = ''.join(random.choice(alphabet) for i in range(length))
    return password

def deleteEntry(module, kp, entry):
    kp.delete_entry(entry)
    kp.save()

def modifyPassword(module, kp, entry, entry_password):
    entry.save_history()
    entry.password = entry_password
    entry.touch(modify=True)
    kp.save()

def createEntry(module, kp, title, username, kgroup, entry_password):
    password = entry_password
    entry = kp.add_entry(kgroup, title, username, password)
    kp.save()
    return entry


if __name__ == '__main__':
    main()
