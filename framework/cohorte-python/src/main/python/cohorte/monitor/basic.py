#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
COHORTE Monitor: Monitor included in the F/M/N process

:author: Thomas Calmant
:copyright: Copyright 2013, isandlaTech
:license: GPLv3
:version: 1.0.0

..

    This file is part of Cohorte.

    Cohorte is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Cohorte is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Cohorte. If not, see <http://www.gnu.org/licenses/>.
"""

# Documentation strings format
__docformat__ = "restructuredtext en"

# Boot module version
__version__ = "1.0.0"

# ------------------------------------------------------------------------------

# Cohorte modules
import cohorte.forker
import cohorte.monitor
import cohorte.monitor.fsm as fsm
import cohorte.repositories
import cohorte.repositories.beans as beans

# Herald
import herald
from herald.beans import Message

# iPOPO Decorators
from pelix.ipopo.decorators import ComponentFactory, Provides, Validate, \
    Invalidate, Requires, Property

# Standard library
import logging
import threading
import uuid

# ------------------------------------------------------------------------------

_logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------

@ComponentFactory("cohorte-monitor-basic-factory")
@Provides((cohorte.monitor.SERVICE_MONITOR,
           cohorte.forker.SERVICE_WATCHER_LISTENER))
@Provides(herald.SERVICE_LISTENER)
@Requires('_config', cohorte.SERVICE_CONFIGURATION_READER)
@Requires('_finder', cohorte.SERVICE_FILE_FINDER)
@Requires('_forker', cohorte.SERVICE_FORKER)
@Requires('_herald', herald.SERVICE_HERALD)
@Requires('_repositories', cohorte.repositories.SERVICE_REPOSITORY_ARTIFACTS,
          aggregate=True)
@Requires('_status', cohorte.monitor.SERVICE_STATUS)
@Property('_filters', herald.PROP_FILTERS,
          (cohorte.monitor.SIGNALS_ISOLATE_PATTERN,
           cohorte.monitor.SIGNALS_PLATFORM_PATTERN))
class MonitorBasic(object):
    """
    Monitor core component: interface to the forker
    """
    def __init__(self):
        """
        Sets up the component
        """
        # Injected services
        self._config = None
        self._finder = None
        self._forker = None
        self._herald = None
        self._repositories = []
        self._status = None

        # Properties
        self._filters = None

        # Node UID
        self._node_uid = None
        self._node_name = None

        # Bundle context
        self._context = None

        # Platform stopping event
        self._platform_stopping = threading.Event()

        # Auto-run isolates
        self._auto_isolates = {}


    def handle_received_signal(self, name, data):
        """
        Handles a signal

        :param name: Signal name
        :param data: Signal data dictionary
        """
        # Platform signals
        if name == cohorte.monitor.SIGNAL_PLATFORM_STOPPING:
            # Platform goes into stopping mode (let the sender do the job)
            self._platform_stopping.set()

        elif name == cohorte.monitor.SIGNAL_STOP_PLATFORM:
            # Platform must stop (new thread)
            threading.Thread(name="platform-stop",
                             target=self._stop_platform).start()

        # Isolate signals
        elif self._node_uid == data['senderNodeUID']:
            # Ignore signals from other nodes
            if name == cohorte.monitor.SIGNAL_ISOLATE_READY:
                # Isolate ready
                self._status.isolate_ready(data['senderUID'])

            elif name == cohorte.monitor.SIGNAL_ISOLATE_STOPPING:
                # Isolate stopping
                self._status.isolate_stopping(data['senderUID'])

            elif name == cohorte.monitor.SIGNAL_ISOLATE_LOST:
                # Isolate signaled as lost
                self._handle_lost(data['signalContent'])


    def ping(self, uid):
        """
        Tells a forker to ping an isolate

        :param uid: UID of the isolate to ping
        :return: True if the forker knows and pings the isolate
        """
        return self._forker.ping(uid)


    def _get_isolate_artifacts(self, kind, level, sublevel):
        """
        Retrieves the list of bundles configured for this isolate
        """
        # Load the isolate model file
        boot_dict = self._config.load_conf_raw(level, sublevel)

        # Parse it
        configuration = self._config.load_boot_dict(boot_dict)

        # Convert configuration bundles to repository artifacts
        return [beans.Artifact(level, bundle.name, bundle.version,
                               bundle.filename)
                for bundle in configuration.bundles]


    def _start_config_isolates(self):
        """
        Starts isolates configured for this node

        :return: True if all isolates have beean started correctly
        """
        try:
            isolates = self._config.read('autorun_isolates.js', True)

        except (IOError, ValueError):
            # Error already logged by the file reader
            return

        if not isolates:
            # No predefined isolates
            _logger.debug("No predefined isolates.")
            return

        all_started = True
        for isolate in isolates:
            all_started |= self._start_config_isolate(isolate)

        return all_started


    def _start_config_isolate(self, isolate):
        """
        Starts a single configured isolate.

        :param isolate: Isolate configuration
        :return: True if the isolate has been started, else False
        """
        # Check isolate node
        if isolate.get('node') != self._node_name:
            return False

        # Check its name
        name = isolate.get('name')
        if not name:
            _logger.warning("Refusing an auto-run isolate without name")
            return False

        # Use/Generate the isolate UID
        uid = isolate.get('custom_uid')
        if not uid:
            uid = str(uuid.uuid4())

        # Store it, to force the forker to use the same UID
        isolate['uid'] = uid

        # Store the isolate configuration
        self._auto_isolates[uid] = isolate

        # Store the isolate in the status
        self._status.add_isolate(uid)

        # Call the forker
        _logger.debug("(Re)Loading predefined isolate: %s (%s)", name, uid)
        self._status.isolate_requested(uid)
        result = self._forker.start_isolate(isolate)

        if result in cohorte.forker.REQUEST_SUCCESSES:
            # Great success !
            self._status.isolate_starting(uid)
            return True

        else:
            # Failed...
            self._status.isolate_gone(uid)
            return False


    def start_isolate(self, name, kind, level, sublevel, bundles=None,
                      uid=None):
        """
        Starts an isolate according to the given elements, or stacks the order
        until a forker appears on the given node

        :param name: Isolate name
        :param kind: The kind of isolate to boot (pelix, osgi, ...)
        :param level: The level of configuration (boot, java, python, ...)
        :param sublevel: Category of configuration (monitor, isolate, ...)
        :param bundles: Extra bundles to install (Bundle beans)
        :param uid: A user-defined isolate UID
        :raise IOError: Unknown/unaccessible kind of isolate
        :raise KeyError: A parameter is missing in the configuration files
        :raise ValueError: Error reading the configuration
        """
        if self._platform_stopping.is_set():
            # Avoid to start new isolates while we are stopping
            return False

        # Compute bundles according to the factories
        if bundles is None:
            bundles = []

        # Find the repository associated to the language
        for repository in self._repositories:
            if repository.get_language() == level:
                break

        else:
            _logger.error("No repository found for language: %s", level)
            return False

        # Get the configured isolate artifacts
        isolate_artifacts = self._get_isolate_artifacts(kind, level, sublevel)

        # Resolve the custom bundles installation
        resolution = repository.resolve_installation(bundles, isolate_artifacts)
        if resolution[2]:
            # Some artifacts are missing
            _logger.error("Missing artifacts: %s", resolution[2])
            return False

        elif resolution[3]:
            # Some extra dependencies are missing
            _logger.warning("Missing extra elements: %s", resolution[3])

        # Clean up resolution
        custom_artifacts = [artifact for artifact in resolution[0]
                            if artifact not in isolate_artifacts]

        # Generate a UID, if necessary
        if not uid:
            uid = uuid.uuid4()

        # Convert the UID into a string
        uid = str(uid)

        # Prepare a configuration
        # Node name and UID will be given by the forker
        config = self._config.prepare_isolate(uid, name, kind,
                                              level, sublevel, custom_artifacts)

        # Store the isolate in the status
        self._status.add_isolate(uid)

        # Talk to the forker
        self._status.isolate_requested(uid)
        result = self._forker.start_isolate(config)

        if result in cohorte.forker.REQUEST_SUCCESSES:
            # Great success !
            self._status.isolate_starting(uid)
            return True

        else:
            # Failed...
            self._status.isolate_gone(uid)
            return False


    def stop_isolate(self, uid):
        """
        Stops the isolate with the given UID

        :param uid: UID of an isolate
        :return: True if the forker knew the isolate
        """
        try:
            self._forker.stop_isolate(uid)
            return True
        except KeyError:
            return False


    def handle_lost_isolate(self, uid):
        """
        A local isolate has been lost
        """
        try:
            # Find the matching configuration
            isolate = self._auto_isolates.pop(uid)

        except KeyError:
            # Not an auto-run isolate: ignore it (let the composer handle it)
            _logger.error("Unknown isolate: %s", uid)
            return

        _logger.warning("Auto-run isolate lost: %s (%s)",
                        isolate.get('name'), uid)

        # Change internal state
        self._status.isolate_gone(uid)

        # Auto-run isolate has been lost: restart it
        self._start_config_isolate(isolate)


    def _handle_lost(self, uid):
        """
        Handles a lost isolate

        :param uid: UID of the lost isolate
        """
        try:
            # Get previous state
            state = self._status.get_state(uid)

        except KeyError:
            # Unknown / Already lost isolate -> do nothing
            _logger.info("Unknown isolate %s lost (or already handled)", uid)
            return

        # Change state
        self._status.isolate_gone(uid)

        if state == fsm.ISOLATE_STATE_STOPPING:
            # "Foreign" isolate stopped nicely
            _logger.info("Isolate %s stopped nicely.", uid)
        else:
            # "Foreign" isolate lost
            _logger.error("Isolate %s lost", uid)


    def _stop_platform(self):
        """
        Stops the whole platform
        """
        if self._platform_stopping.is_set():
            # Already stopping
            return

        _logger.critical(">>> PLATFORM STOPPING <<<")

        # Set this monitor in stopping state
        self._platform_stopping.set()

        # Set the forker in stopping state
        self._forker.set_platform_stopping()

        # Send the platform stopping signal to other monitors
        self._herald.fire_group(
            'monitors', Message(cohorte.monitor.SIGNAL_PLATFORM_STOPPING))

        # Tell the forker to stop the running isolates
        for uid in self._status.get_running():
            self._forker.stop_isolate(uid)

        # Stop this isolate
        self._context.get_bundle(0).stop()


    def _load_top_composer(self):
        """
        Installs and starts the top composer bundles
        """
        # Get installed bundles
        installed = set(bundle.get_symbolic_name()
                        for bundle in self._context.get_bundles())

        # Read the top composer configuration file
        top_config = self._config.read("composer/python-top.js")

        # Extract bundle names
        bundles = [bundle['name'] for bundle in top_config['bundles']]

        # Start new bundles
        for name in bundles:
            if name not in installed:
                self._context.install_bundle(name).start()


    @Validate
    def validate(self, context):
        """
        Component validated
        """
        self._context = context

        # Set to PROP_NODE_UID when ready
        self._node_uid = context.get_property(cohorte.PROP_NODE_UID)
        self._node_name = context.get_property(cohorte.PROP_NODE_NAME)

        _logger.info("Monitor core validated")

        # Start predefined isolates
        self._start_config_isolates()

        # Start the Top Composer
        if context.get_property(cohorte.PROP_RUN_TOP_COMPOSER):
            self._load_top_composer()


    @Invalidate
    def invalidate(self, context):
        """
        Component invalidated
        """
        # Kill auto-run isolates
        for uid in tuple(self._auto_isolates.keys()):
            self._forker.stop_isolate(uid)

        # Clean up
        self._auto_isolates.clear()
        self._node_uid = None
        self._node_name = None
        self._context = None
        _logger.info("Monitor core invalidated")
