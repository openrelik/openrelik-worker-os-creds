# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
import subprocess
import tempfile

from openrelik_worker_common.reporting import Report, Priority
from openrelik_worker_common.password_utils import bruteforce_password_hashes

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def analyze_accts(files: list[str]) -> Report:
    """Extract accounts from Windows registry store.

    Args:
      files (list[dict]): List of collected files.

    Returns:
        report (Report): The analysis report.
    """
    file_path = os.path.commonpath([y.get('path', '') for y in files])
    (system, sam) = _extract_system_and_sam_from_input_files(files)

    (creds, hashnames) = _extract_windows_hashes(location=file_path,
                                                 system=system,
                                                 sam=sam)

    if os.path.isfile(os.path.join(file_path, 'ntds.dit')):
        try:
            (adcreds, adhashnames) = _extract_ad_hashes(result, location)
            creds.extend(adcreds)
            hashnames = hashnames | adhashnames
        except exception:
            extra_summary = " Unable to extract AD credentials (not a DC?)."

    return analyse_windows_creds(creds, hashnames)


def _extract_system_and_sam_from_input_files(files):
    system = "SYSTEM"
    sam = "SAM"
    for file in files:
        if file.get('display_name', '').upper() == 'SAM':
            sam = file.get('uuid', 'SAM')
        if file.get('display_name', '').upper() == 'SYSTEM':
            system = file.get('uuid', 'SYSTEM')
    return (system, sam)


def _extract_windows_hashes(location: str,
                            system: str = "SYSTEM",
                            sam: str = "SAM"):
    """Dump the secrets from the Windows registry files.

    Args:
        location (str): File path to the extracted registry files.
        system (str): Name of SYSTEM registry hive file.
        sam (str): Name of SAM registry hive file.

    Raises:
        RuntimeError

    Returns:
        creds (list): List of strings containing raw extracted credentials
        hashnames (dict): Dict mapping hash back to username for convenience.
    """

    # Default (empty) hash
    IGNORE_CREDS = ['31d6cfe0d16ae931b73c59d7e0c089c0']

    hash_file = os.path.join(tempfile.gettempdir(), 'windows_hashes')
    cmd = [
        'secretsdump.py', '-system',
        os.path.join(location, system), '-sam',
        os.path.join(location, sam), '-hashes', 'lmhash:nthash', 'LOCAL',
        '-outputfile', hash_file
    ]

    ret_code = execution_helper(cmd)
    logger.debug(f"Windows Hashes return code: {ret_code}")

    creds = []
    hashnames = {}
    hash_file = hash_file + '.sam'
    if os.path.isfile(hash_file):
        with open(hash_file, 'r') as fh:
            for line in fh:
                (username, _, _, passwdhash, _, _, _) = line.split(':')
                if passwdhash in IGNORE_CREDS:
                    continue
                creds.append(line.strip())
                if passwdhash in hashnames:
                    hashnames[
                        passwdhash] = hashnames[passwdhash] + ", " + username
                else:
                    hashnames[passwdhash] = username
        os.remove(hash_file)
    else:
        raise RuntimeError('Extracted hash file not found.')

    return (creds, hashnames)


def _extract_ad_hashes(location):
    """Dump the secrets from the Windows Active Directory NTDS file.

    Args:
        location (str): File path to the extracted registry files.

    Raises:
        RuntimeError

    Returns:
        creds (list[str]): List of strings containing raw extracted credentials
        hashnames (dict): Dict mapping hash back to username for convenience.
    """

    # Default (empty) hash
    IGNORE_CREDS = ['31d6cfe0d16ae931b73c59d7e0c089c0']

    hash_file = os.path.join(tempfile.gettempdir(), 'ad_hashes')
    cmd = [
        'secretsdump.py', '-system',
        os.path.join(location, 'SYSTEM'), '-ntds',
        os.path.join(location, 'ntds.dit'), '-hashes', 'lmhash:nthash',
        'LOCAL', '-outputfile', hash_file
    ]

    ret_code = execution_helper(cmd)
    logger.debug(f"AD Hashes return code: {ret_code}")

    creds = []
    hashnames = {}
    hash_file = hash_file + '.ntds'
    if os.path.isfile(hash_file):
        with open(hash_file, 'r') as fh:
            for line in fh:
                (username, _, _, passwdhash, _, _, _) = line.split(':')
                if passwdhash in IGNORE_CREDS:
                    continue
                creds.append(line.strip())
                if passwdhash in hashnames:
                    hashnames[
                        passwdhash] = hashnames[passwdhash] + ", " + username
                else:
                    hashnames[passwdhash] = username
        os.remove(hash_file)
    else:
        raise RuntimeError('Extracted hash file not found.')

    return (creds, hashnames)


def analyse_windows_creds(creds, hashnames, timeout=300):
    """Attempt to brute force extracted Windows credentials.

    Args:
        creds (list[str]): List of strings containing raw extracted credentials
        hashnames (dict[str, str]): Dict mapping hash back to username for convenience.
        timeout (int): How long to spend cracking.

    Returns:
      Report
    """
    report = Report("Windows Account Analyzer")
    summary_section = report.add_section()
    details_section = report.add_section()
    priority = Priority.LOW

    # 1000 is "NTLM"
    weak_passwords = bruteforce_password_hashes(
        creds,
        tmp_dir=None,
        password_list_file_path="/openrelik/password.lst",
        password_rules_file_path="/openrelik/openrelik-password-cracking.rules",
        timeout=timeout,
        extra_args='-m 1000')

    if weak_passwords:
        priority = Priority.CRITICAL
        report.summary = f'Registry analysis found {len(weak_passwords):d} weak password(s)'
        line = f'{len(weak_passwords):n} weak password(s) found:'
        details_section.add_bullet(line)
        for password_hash, plaintext in weak_passwords:
            if password_hash in hashnames:
                line = """User '{0:s}' with password '{1:s}'""".format(
                    hashnames[password_hash], plaintext)
                details_section.add_bullet(line, level=2)
    else:
        report.summary = "No weak passwords found"

    summary_section.add_paragraph(report.summary)
    return report


def execution_helper(cmd):
    proc = subprocess.Popen(cmd,
                            stderr=subprocess.PIPE,
                            stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if stderr:
        logger.warning(str(stderr))

    return proc.returncode
