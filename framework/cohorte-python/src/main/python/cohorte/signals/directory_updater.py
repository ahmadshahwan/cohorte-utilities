#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
Python implementation of the PSEM2M Directory updater

Created on 18 juin 2012

:author: Thomas Calmant
:license: GPLv3
"""

# Documentation strings format
__docformat__ = "restructuredtext en"

# Boot module version
__version__ = "1.0.0"

# ------------------------------------------------------------------------------

# COHORTE constants
import cohorte.forker
import cohorte.monitor
import cohorte.signals

# Pelix/iPOPO
from pelix.ipopo.decorators import ComponentFactory, Requires, Validate, \
    Invalidate

# Standard library
import logging
import threading

# ------------------------------------------------------------------------------

_logger = logging.getLogger(__name__)

UPDATE_SIGNALS = (cohorte.signals.SIGNAL_PATTERN,
                  cohorte.monitor.SIGNAL_ISOLATE_STOPPING,
                  cohorte.monitor.SIGNAL_ISOLATE_LOST,
                  cohorte.forker.SIGNAL_FORKER_STOPPING,
                  cohorte.forker.SIGNAL_FORKER_LOST)

# ------------------------------------------------------------------------------

@ComponentFactory("cohorte-signals-directory-updater-factory")
@Requires("_directory", cohorte.SERVICE_SIGNALS_DIRECTORY)
@Requires("_receiver", cohorte.SERVICE_SIGNALS_RECEIVER)
@Requires("_sender", cohorte.SERVICE_SIGNALS_SENDER)
class DirectoryUpdater(object):
    """
    Directory update component
    """
    def __init__(self):
        """
        Constructor
        """
        self._directory = None
        self._receiver = None
        self._sender = None

        # Lock to have a clean directory during signals handling
        self._lock = threading.Lock()


    def _grab_directory(self, host, port, ignored_node_uid=None):
        """
        Sends a directory dump signal to the dumper on local host.

        If ignored_host is not None, the address corresponding to it in the
        dumped directory won't be stored.

        :param host: Directory dumper host address
        :param port: Directory signal listener port
        :param ignored_node_uid: The address for this node UID must be ignored
        """
        # Prepare pre-registration content, without propagation
        content = self._prepare_registration_content(False)

        # Send the dump signal, with a registration content
        # -> we give 5 attempts (~15 seconds) for the dumper to reply
        max_attempts = 5
        attempts = 0
        while attempts < max_attempts:
            attempts += 1
            sig_results = self._sender.send_to(cohorte.signals.SIGNAL_DUMP,
                                               content, host, port)
            if not sig_results or not sig_results["results"]:
                # No result: the dumper might be busy
                _logger.warning("Nothing returned by the directory dumper "
                                "(%d/%d)", attempts, max_attempts)

            else:
                # Got it
                _logger.debug("Grabbed the directory after %d attempts",
                              attempts)
                break

        # Local information
        local_isolate_uid = self._directory.get_isolate_uid()
        local_node_uid = self._directory.get_local_node()

        # Get the first result only
        results = sig_results["results"]
        if len(results) > 1:
            _logger.warning("More than one result found. Ignoring others")

        result = results[0]

        # 1. Filter the nodes
        ignored_nodes = (ignored_node_uid, local_node_uid)

        # 2. Filter the UIDs
        ignored_uids = (local_isolate_uid,)

        # 3. Call the directory, to do all the update at once
        self._directory.store_dump(result, ignored_nodes, ignored_uids)

        # 4. Now, we can send our registration signal
        self._send_registration_to_all(True)


    def _grab_remote_directory(self, signal_data):
        """
        Retrieves the directory of a remote isolate.

        This method is called after a CONTACT signal has been received from a
        forker.

        :param signal_data: The received contact signal
        """
        # Only monitors can send us contacts
        remote_name = signal_data["senderName"]
        if remote_name != cohorte.FORKER_NAME:
            _logger.warning("Contacts must be made by a forker, not %s",
                            remote_name)
            return

        # Get information on the sender
        remote_uid = signal_data["senderUID"]
        remote_address = signal_data["senderAddress"]
        remote_node_uid = signal_data["senderNodeUID"]

        _logger.debug("Received request from %s (%s) to dump directory",
                      remote_uid, remote_node_uid)

        # Get the dumper port
        content = signal_data["signalContent"]
        remote_port = content["port"]
        if not remote_port:
            _logger.warning("No port given")
            return

        # Store the remote node
        self._directory.set_node_address(remote_node_uid, remote_address)

        # Grab the directory
        self._grab_directory(remote_address, remote_port, remote_node_uid)


    def _prepare_registration_content(self, propagate):
        """
        Prepares the registration signal content.

        :param propagate: If true, the receivers of this signal will re-emit it
        :return: The content for a registration signal
        """
        # Beat confirmation
        uid = self._directory.get_isolate_uid()
        name = self._directory.get_isolate_name(uid)

        return {"uid": uid,
                "name": name,
                "address": None,  # <- No address when sending
                "node_uid": self._directory.get_local_node(),
                "node_name": self._directory.get_node_name(),
                "port": self._receiver.get_access_info()[1],
                "propagate": propagate}


    def _register_isolate(self, signal_data):
        """
        Registers an isolate according to the given map

        :param signal_data: The received signal
        :return: True if the isolate has been registered
        """
        sender_id = signal_data["senderUID"]
        content = signal_data["signalContent"]

        isolate_uid = content["uid"]
        if isolate_uid == self._directory.get_isolate_uid():
            # Ignore self-registration
            return False

        node_uid = content["node_uid"]
        node_name = content["node_name"]
        if node_uid == signal_data["senderNodeUID"]:
            # If both the registered and the registrar are on the same node,
            # use the sender address to update the node access
            address = signal_data["senderAddress"]

        else:
            # Else: use the address indicated in the signal, or use the sender
            # address
            address = content.get("address", None)
            if not address:
                # Address could be empty, so don't use the dict.get() parameter
                address = signal_data["senderAddress"]

        # 1. Update the node host
        self._directory.set_node_address(node_uid, address)
        self._directory.set_node_name(node_uid, node_name)

        # 2. Register the isolate
        registered = self._directory.register_isolate(isolate_uid,
                                                      content["name"],
                                                      node_uid,
                                                      content["port"])

        # 2b. Acknowledge the registration, even if we knew it before
        if self._directory.is_registered(isolate_uid):
            if sender_id == isolate_uid:
                # Case 1: we got the registration from the isolate itself
                # -> Send a SYN-ACK
                self._sender.post(cohorte.signals.SIGNAL_REGISTER_SYNACK, None,
                                  isolate=isolate_uid)

            elif registered:
                # Case 2: we got the registration by propagation
                # -> Send a REGISTER
                self._sender.post(cohorte.signals.SIGNAL_REGISTER,
                                  self._prepare_registration_content(False),
                                  isolate=isolate_uid)

        else:
            _logger.debug("NOT REGISTERED: %s", isolate_uid)

        # 3. Propagate the registration, if needed
        if content["propagate"]:
            # Propagate only once...
            content["propagate"] = False

            # Indicate the address we used for the registration
            content["address"] = address

            self._sender.post(cohorte.signals.SIGNAL_REGISTER, content,
                              dir_group=cohorte.signals.GROUP_OTHERS,
                              excluded=[isolate_uid])

        return registered


    def _send_registration_to_all(self, propagate):
        """
        Sends the registration signal to all known isolates

        :param propagate: If true, the receivers of this signal will re-emit it
        """
        content = self._prepare_registration_content(propagate)

        # Send the registration signal
        results = self._sender.send(cohorte.signals.SIGNAL_REGISTER, content,
                                    dir_group=cohorte.signals.GROUP_OTHERS)

        if not results:
            _logger.warning("Registration signal not sent/received")

        else:
            _logger.debug("Registration sent to: %s",
                          results[0].keys())


    def handle_received_signal(self, name, signal_data):
        """
        Called when a remote services signal is received

        :param name: Signal name
        :param signal_data: Signal content
        """
        sender_uid = signal_data["senderUID"]

        if name == cohorte.signals.SIGNAL_DUMP:
            with self._lock:
                # Register the incoming isolate
                self._register_isolate(signal_data)

                # Dump the directory
                return self._directory.dump()

        elif name == cohorte.signals.SIGNAL_REGISTER:
            with self._lock:
                # Isolate registration
                self._register_isolate(signal_data)

        elif name == cohorte.signals.SIGNAL_REGISTER_SYNACK:
            with self._lock:
                # Send the final acknowledgment
                self._sender.post(cohorte.signals.SIGNAL_REGISTER_ACK, None,
                                  isolate=sender_uid)

                # Notify listeners
                self._directory.validate_isolate_presence(sender_uid)

        elif name == cohorte.signals.SIGNAL_REGISTER_ACK:
            with self._lock:
                # Our acknowledgment has been received
                self._directory.validate_isolate_presence(sender_uid)

        elif name == cohorte.signals.SIGNAL_CONTACT:
            # A contact has been signal, ask for a remote directory dump
            # -> Forker only
            with self._lock:
                self._grab_remote_directory(signal_data)

        elif name in (cohorte.monitor.SIGNAL_ISOLATE_STOPPING,
                      cohorte.monitor.SIGNAL_ISOLATE_LOST):
            # Stopping / lost isolate
            with self._lock:
                # Unregister the isolate
                isolate_uid = signal_data["signalContent"]
                if isolate_uid:
                    self._directory.unregister_isolate(isolate_uid)

        elif name in (cohorte.forker.SIGNAL_FORKER_STOPPING,
                      cohorte.forker.SIGNAL_FORKER_LOST):
            # Stopping / lost forker
            with self._lock:
                # Unregister the forker and its isolates
                forker_uid = signal_data["signalContent"]['uid']
                isolates = signal_data["signalContent"]['isolates']

                if forker_uid:
                    self._directory.unregister_isolate(forker_uid)

                for isolate_uid in isolates:
                    if isolate_uid:
                        self._directory.unregister_isolate(isolate_uid)


    @Invalidate
    def invalidate(self, context):
        """
        Component invalidated
        """
        # Unregister to isolate registration signals
        for signal in UPDATE_SIGNALS:
            self._receiver.unregister_listener(signal, self)


    @Validate
    def validate(self, context):
        """
        Component validate
        """
        # Register to isolate registration signals
        for signal in UPDATE_SIGNALS:
            self._receiver.register_listener(signal, self)

        # Get the local dumper port
        dump_port = context.get_property(cohorte.PROP_DUMPER_PORT)
        if not dump_port:
            _logger.warning("No local dumper port found.")
            # Can't grab...

        else:
            # Grab from local host
            self._grab_directory("localhost", int(dump_port))
