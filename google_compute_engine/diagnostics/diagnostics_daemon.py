#!/usr/bin/python
# Copyright 2018 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Listens on the Metadata Server for cues to trigger the diagnostics tool."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import datetime
import json
import logging.handlers
import optparse
import subprocess

from google_compute_engine import config_manager
from google_compute_engine import constants
from google_compute_engine import file_utils
from google_compute_engine import logger
from google_compute_engine import metadata_watcher

LOCKFILE = constants.LOCALSTATEDIR + '/lock/google_diagnostics.lock'

class DiagnosticsDaemon(object):
  """Handle triggering diagnostics based on changes to the metadata."""

  diagnose_token = 'instance/attributes/diagnostics'
  instance_diagnostics_token = 'instance/attributes/enable-diagnostics'
  project_diagnostics_token = 'project/attributes/enable-diagnostics'
  instance_diagnostics_enabled = None
  project_diagnostics_enabled = None

  def __init__(self, debug=False):
    """Constructor.

    Args:
      debug: bool, True if debug output should write to the console.
    """
    facility = logging.handlers.SysLogHandler.LOG_DAEMON
    self.logger = logger.Logger(
        name='google-diagnostics', debug=debug, facility=facility)
    self.watcher = metadata_watcher.MetadataWatcher(logger=self.logger)
    try:
      with file_utils.LockFile(LOCKFILE):
        self.logger.info('Starting Google Diagnostics daemon.')
        self.watcher.WatchMetadata(
            self.HandleDiagnostics, metadata_key=self.diagnose_token,
            recursive=False)
        self.watcher.WatchMetadata(
            self.SetInstanceDiagnosticsEnabled,
            metadata_key=self.instance_diagnostics_token,
            recursive=False)
        self.watcher.WatchMetadata(
            self.SetProjectDiagnosticsEnabled,
            metadata_key=self.project_diagnostics_token,
            recursive=False)
    except (IOError, OSError) as e:
      self.logger.warning(str(e))

  def _RequestExpired(self, diagnostics_request):
    """Checks if the diagnostics request has expired.

    Checks the expiration time of the request against the current time. It
    marks the request as expired if the request has a valid expiration time,
    and that time has since passed.

    Args:
      diagnostics_request: dict, request containing the parameters for
        triggering diagnostics.

    Returns:
      bool, True if the request has a valid expiration timestamp and that time
        has since passed. False otherwise.
    """
    if 'expireOn' not in diagnostics_request:
      self.logger.info('No expiration timestamp. Not expiring key.')
      return False

    expire_str = diagnostics_request['expireOn']
    format_str = '%Y-%m-%dT%H:%M:%SZ'
    try:
      expire_time = datetime.datetime.strptime(expire_str, format_str)
    except ValueError:
      self.logger.warning(
          'Expiration timestamp "%s" not in the format %s. Not expiring key.',
          expire_str, format_str)
      return False

    return datetime.datetime.utcnow() > expire_time

  def _DiagnosticsEnabled(self):
    """Determine if diagnostics are enabled.

    Prioritizes the instance configuration, followed by instance level metadata,
    then the project level metadata. If all are unset, diagnostics are assumed
    to be disabled.

    Returns:
      True if diagnostics are enabled, and False otherwise.
    """
    instance_config = config_manager.ConfigManager()
    if instance_config.config.has_option('Diagnostics', 'enable_diagnostics'):
      return instance_config.GetOptionBool('Diagnostics', 'enable_diagnostics')

    if instance_diagnostics_enabled is not None:
      return instance_diagnostics_enabled

    if project_diagnostics_enabled is not None:
      return project_diagnostics_enabled
    return False

  def SetInstanceDiagnosticsEnabled(self, enable):
    """Handles updates to instance level metadata of diagnostics being enabled.

    Args:
      enable: bool, the value of the instance level metadata determining if
        diagnostics are enabled or disabled.
    """
    self.instance_diagnostics_enabled = enable

  def SetProjectDiagnosticsEnabled(self, enable):
    """Handles updates to project level metadata of diagnostics being enabled.

    Args:
      enable: bool, the value of the project level metadata determining if
        diagnostics are enabled or disabled.
    """
    self.project_diagnostics_enabled = enable

  def HandleDiagnostics(self, response):
    """Responds to a diagnostics request.

    Args:
      response: string, the metadata containing the json diagnostics request.
    """
    self.logger.info('Diagnostics request sent: %s.' % response)
    if not self._DiagnosticsEnabled():
      self.logger.info('Diagnostics not enabled. Ignoring diagnostics request.')
      return

    try:
      diagnostics_request = json.loads(response)
    except ValueError:
      self.logger.debug('Invalid JSON %s. Ignoring diagnostics request', response)
      return

    if self._RequestExpired(diagnostics_request):
      self.logger.debug('Ignoring expired request %s.', response)
      return

    if 'signedUrl' not in diagnostics_request:
      self.logger.debug('Invalid request: does not contain key "signedUrl".')
      return

    command = [
        '/sbin/gce-diagnostics',
        '-signedUrl',
        diagnostics_request['signedUrl']
    ]
    if 'trace' in diagnostics_request and diagnostics_request['trace']:
      command.append('-trace')

    try:
      subprocess.call(command)
    except OSError:
      self.logger.warning('Failed to run diagnostics. The "gce-diagnostics"'
                          'command is likely not installed.')
    else:
      self.logger.info('Successfully ran diagnostics.')


def main():
  parser = optparse.OptionParser()
  parser.add_option(
      '-d', '--debug', action='store_true', dest='debug',
      help='print debug output to the console.')
  (options, _) = parser.parse_args()
  instance_config = config_manager.ConfigManager()
  if instance_config.GetOptionBool('Daemons', 'diagnostics_daemon'):
    DiagnosticsDaemon(debug=bool(options.debug))

if __name__ == '__main__':
  main()

