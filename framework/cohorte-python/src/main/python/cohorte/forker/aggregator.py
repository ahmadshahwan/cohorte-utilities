#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
COHORTE Forker: Forker aggregator

To be used in monitors.
Uses multicast packets.

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

# COHORTE utilities
import cohorte.utils.multicast as multicast

# iPOPO Decorators
from pelix.ipopo.decorators import ComponentFactory, Provides, Validate, \
    Invalidate, Requires, Property, Bind

# Pelix utilities
import pelix.framework
import pelix.threadpool
from pelix.utilities import to_unicode

# Standard library
import logging
import select
import struct
import threading
import time

# ------------------------------------------------------------------------------

_logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------

class MulticastReceiver(object):
    """
    A multicast datagram receiver
    """
    def __init__(self, group, port, callback):
        """
        Sets up the receiver

        :param group: Multicast group to listen
        :param port: Multicast port
        :param handler: Method to call back once a packet is received
        """
        # Parameters
        self._group = group
        self._port = port
        self._callback = callback

        # Reception loop
        self._stop_event = threading.Event()
        self._thread = None

        # Socket
        self._socket = None


    def start(self):
        """
        Starts listening to the socket

        :return: True if the socket has been created
        """
        # Create the multicast socket (update the group)
        self._socket, self._group = multicast.create_multicast_socket(\
                                                        self._group, self._port)

        # Start the listening thread
        self._stop_event.clear()
        self._thread = threading.Thread(target=self.__read,
                                        name="MulticastReceiver-{0}"\
                                             .format(self._port))
        self._thread.start()


    def stop(self):
        """
        Stops listening to the socket
        """
        # Stop the loop
        self._stop_event.set()

        # Join the thread
        self._thread.join()
        self._thread = None

        # Close the socket
        multicast.close_multicast_socket(self._socket, self._group)


    def _handle_heartbeat(self, sender, data):
        """
        Handles a raw heartbeat

        :param sender: Sender (address, port) tuple
        :param data: Raw packet data
        """
        # Prefix
        result, data = self._unpack("<BH", data)
        if result[0] != 1:
            # Not a heart beat
            _logger.warning("Invalid heart beat from %s", sender)
            return

        # Get the port
        port = result[1]

        # Get the strings
        application_id, data = self._unpack_string(data)
        forker_uid, data = self._unpack_string(data)
        node_id, data = self._unpack_string(data)
        node_name, data = self._unpack_string(data)

        # Call the callback method
        try:
            self._callback(forker_uid, application_id, node_id, node_name,
                           sender[0], port)

        except Exception as ex:
            _logger.exception("Error notifying callback: %s", ex)


    def _unpack(self, fmt, data):
        """
        Calls struct.unpack().

        Returns a tuple containing the result tuple and the subset of data
        containing the unread content.

        :param fmt: The format of data
        :param data: Data to unpack
        :return: A tuple (result tuple, unread_data)
        """
        size = struct.calcsize(fmt)
        read, unread = data[:size], data[size:]
        return (struct.unpack(fmt, read), unread)


    def _unpack_string(self, data):
        """
        Unpacks the next string from the given data

        :param data: A datagram, starting at a string size
        :return: A (string, unread_data) tuple
        """
        # Get the size of the string
        result, data = self._unpack("<H", data)
        size = result[0]

        # Read it
        string_bytes = data[:size]

        # Convert it
        return (to_unicode(string_bytes), data[size:])


    def __read(self):
        """
        Reads packets from the socket
        """
        # Set the socket as non-blocking
        self._socket.setblocking(0)

        while not self._stop_event.is_set():
            # Watch for content
            ready = select.select([self._socket], [], [], 1)
            if ready[0]:
                # Socket is ready
                data, sender = self._socket.recvfrom(1024)
                try:
                    self._handle_heartbeat(sender, data)

                except Exception as ex:
                    _logger.exception("Error handling the heart beat: %s", ex)

# ------------------------------------------------------------------------------

@ComponentFactory("cohorte-forker-aggregator-factory")
@Provides(cohorte.forker.SERVICE_AGGREGATOR)
@Provides(cohorte.signals.SERVICE_ISOLATE_PRESENCE_LISTENER)
@Requires('_directory', cohorte.SERVICE_SIGNALS_DIRECTORY)
@Requires('_receiver', cohorte.SERVICE_SIGNALS_RECEIVER)
@Requires('_sender', cohorte.SERVICE_SIGNALS_SENDER)
@Requires('_listeners', cohorte.forker.SERVICE_FORKER_LISTENER, True, True)
@Property('_group', 'multicast.group', '239.0.0.1')
@Property('_port', 'multicast.port', 42000)
@Property('_forker_ttl', 'forker.ttl', 5)
class ForkerAggregator(object):
    """
    Forker aggregator: listens for multicast datagrams to register forkers or
    to consider them as lost.
    """
    def __init__(self):
        """
        Sets up the component
        """
        # Injected services
        self._directory = None
        self._receiver = None
        self._sender = None
        self._listeners = None

        # Local forker UID
        self._local_uid = None

        # Multicast receiver
        self._multicast = None

        # Properties
        self._group = "239.0.0.1"
        self._port = 42000
        self._forker_ttl = 10

        # Threads
        self._stopped = threading.Event()
        self._lst_thread = None
        self._events_thread = None

        # Forker UID -> Last Time Seen
        self._forker_lst = {}
        self._lst_lock = threading.RLock()

        # Isolate UID -> Forker
        self._isolate_forker = {}


    @Bind
    def bind(self, service, reference):
        """
        A dependency has been bound

        :param service: Bound service
        :param reference: Associated ServiceReference
        """
        specs = reference.get_property(pelix.framework.OBJECTCLASS)
        if cohorte.forker.SERVICE_FORKER_LISTENER in specs:
            # Forker listener bound
            if hasattr(service, "forker_ready"):
                # Forker presence method implemented
                for uid in self._forker_lst:
                    # Notify the presence of all known forkers
                    node = self._directory.get_isolate_node(uid)
                    service.forker_ready(uid, node)


    def set_platform_stopping(self):
        """
        Sends the signal to all forkers that the platform is shutting down
        """
        self._sender.fire(cohorte.monitor.SIGNAL_STOP_PLATFORM, None,
                          dir_group=cohorte.signals.GROUP_FORKERS)


    def start_isolate(self, uid, node, kind, configuration):
        """
        Requests the forker on the given node to start an isolate

        :param uid: UID of the isolate to start
        :param node: ID of the node that will host the isolate
        :param kind: Kind of isolate
        :param configuration: The complete configuration dictionary
        :return: The forker result
        """
        forker = self._get_forker(node, kind)
        if forker is None:
            return cohorte.forker.REQUEST_NO_MATCHING_FORKER

        # Send the order
        result = self._call_forker(forker, cohorte.forker.SIGNAL_START_ISOLATE,
                                   {"isolateDescr": configuration}, 10)

        if result in cohorte.forker.REQUEST_SUCCESSES:
            # Store the isolate in case of success only
            self._isolate_forker[uid] = forker

        return result


    def is_alive(self, uid):
        """
        Uses a forker to test if the isolate process is alive

        :param uid: An isolate UID
        :return: True if the isolate process is active
        """
        forker = self._isolate_forker.get(uid)
        if forker is None:
            _logger.error("No forker to ping isolate %s", uid)
            return False

        return self._call_forker(forker, cohorte.forker.SIGNAL_PING_ISOLATE,
                                 {"uid": uid}, 2) == 0


    def stop_isolate(self, uid):
        """
        Stops the isolate with the given UID using its associated forker.
        Sends the stop signal to isolate itself if no forker is found.

        :param uid: UID of the isolate to stop
        :return: True if the forker associated to the UID has been contacted
        """
        forker = self._isolate_forker.get(uid)
        if forker is None:
            # No forker: fire a signal to the isolate
            self._sender.fire(cohorte.monitor.SIGNAL_STOP_ISOLATE, None, uid)
            _logger.warning("No forker associated to isolate %s", uid)
            return False

        else:
            # Tell the forker to stop the isolate
            if self._sender.fire(cohorte.monitor.SIGNAL_STOP_ISOLATE,
                                 {'uid': uid}, forker):
                # Signal received
                return True

            else:
                # Signal lost
                self._sender.fire(cohorte.monitor.SIGNAL_STOP_ISOLATE, None,
                                  uid)
                _logger.warning("Forker %s didn't received order to stop %s",
                                forker, uid)
                return False


    def stop_forkers(self):
        """
        Sends a stop signal to all forkers
        """
        self._sender.fire(cohorte.forker.SIGNAL_STOP_FORKER, None,
                          dir_group=cohorte.signals.GROUP_FORKERS)


    def register_forker(self, uid, node_uid, node_name, host, port):
        """
        Registers a forker in the directory.

        :param uid: Forker UID
        :param node_uid: UID of the node hosting the forker
        :param node_name: Name of the node hosting the forker
        :param address: Node address
        :param port: Forker access port
        """
        # Update the node host
        self._directory.set_node_address(node_uid, host)

        # Update the node name
        self._directory.set_node_name(node_uid, node_name)

        # Register the forker
        if self._directory.register_isolate(uid, cohorte.forker.FORKER_NAME,
                                            node_uid, port):
            # New isolate: send it a SYN-ACK
            self._sender.fire(cohorte.signals.SIGNAL_REGISTER_SYNACK, None, uid)

            # Fresh forker: send a contact signal
            self._send_contact(host, port)

            _logger.debug("Newly registered forker ID=%s Node=%s/%s Port=%d",
                          uid, node_uid, node_name, port)

        else:
            _logger.debug("Already registered forker ID=%s", uid)

        # Notify listeners
        self._notify_listeners(uid, node_uid, True)


    def _notify_listeners(self, uid, node, registered):
        """
        Notifies listeners of a forker event

        :param uid: UID of a forker
        :param node: Node hosting the forker
        :param registered: If True, the forker has been registered, else lost
        """
        if not self._listeners:
            # Nothing to do
            return

        # Compute the method name
        if registered:
            method_name = "forker_ready"
        else:
            method_name = "forker_lost"

        # Enqueue the notification call
        self._events_thread.enqueue(self.__notification, self._listeners[:],
                                    method_name, uid, node)


    def __notification(self, listeners, method_name, uid, node):
        """
        Listeners notification loop

        :param listeners: List of listeners to call
        :param method: Name of the method to call in listeners
        :param uid: UID of a forker
        :param node: Node hosting the forker
        """
        for listener in listeners:
            # Get the listener method
            method = getattr(listener, method_name, None)
            if method is not None:
                try:
                    # Call it
                    method(uid, node)

                except Exception as ex:
                    _logger.exception("A forker event listener failed: %s",
                                      ex)



    def _send_contact(self, host, port):
        """
        Sends a CONTACT signal to the given access point.

        :param host: A host address
        :param port: A signal access port
        """
        try:
            # Get access info
            local_port = self._receiver.get_access_info()[1]

            # Send the contact signal
            result = self._sender.send_to(cohorte.signals.SIGNAL_CONTACT,
                                          {"port": local_port}, host, port)
            if not result:
                _logger.warning("No response from forker at host=%s port=%d",
                                host, port)

        except Exception as ex:
            # Just log the exception
            _logger.error("Error sending contact signal: %s", ex)


    def _send_forker_lost(self, uid):
        """
        Sends a "forker lost" signal

        :param uid: UID of the lost forker
        """
        # Remove the references to the forker in the LST
        with self._lst_lock:
            if uid in self._forker_lst:
                del self._forker_lst[uid]

        # Compute the forker node
        node = self._directory.get_isolate_node(uid)

        # Get the list of its isolates
        isolates = [entry[0] for entry in self._isolate_forker.items()
                    if entry[1] == uid]

        _logger.debug("Lost forker %s for node %s (%s isolates)",
                      uid, node, len(isolates))

        # Compute the signal exclusion list
        excluded = [uid]
        excluded.extend(isolates)

        # Prepare the signal content
        content = {'uid': uid, 'node': node, 'isolates': isolates}

        # Send the signal to all but the lost forker and its isolates
        self._sender.post(cohorte.forker.SIGNAL_FORKER_LOST,
                          content, dir_group=cohorte.signals.GROUP_ALL,
                          excluded=excluded)

        # Clean up details about this forker
        for isolate in isolates:
            del self._isolate_forker[isolate]


    def _call_forker(self, uid, signal, data, timeout):
        """
        Posts an order to the given forker and waits for the result.
        Returns FORKER_REQUEST_TIMEOUT if the time out expires before.

        :param uid: Forker UID
        :param signal: Name of the signal to send
        :param data: Content of the signal
        :param timeout: Maximum time to wait for a response (in seconds)
        """
        future = self._sender.post(signal, data, uid)

        try:
            # Wait for a result
            results = future.result(timeout)
            if not results:
                _logger.warning("No access to the forker %s", uid)
                return cohorte.forker.REQUEST_ERROR

        except OSError:
            # Timeout
            _logger.error("Forker %s timed out sending signal %s", uid, signal)
            return cohorte.forker.REQUEST_TIMEOUT

        else:
            try:
                # Get the result
                result = results[0][uid]['results'][0]
                return int(result)

            except (KeyError, IndexError, ValueError):
                # No result
                return cohorte.forker.REQUEST_NO_RESULT


    def _get_forker(self, node, kind):
        """
        Finds the first isolate with a forker ID on the given node

        :param node: Name of a node
        :param kind: Kind the forker must handle
        :return: The first matching UID or None
        """
        # get_name_uids() returns a generator
        forkers = self._directory.get_name_uids(cohorte.forker.FORKER_NAME)

        if node is None:
            # No node given, get the first one found
            return next(forkers)

        else:
            for uid in forkers:
                if self._directory.get_isolate_node(uid) == node:
                    # Found a forker for the node
                    return uid


    def _handle_heartbeat(self, uid, application_id, node_uid, node_name,
                          host, port):
        """
        Handles a decoded heartbeat

        :param uid: UID of the forker
        :param application_id: ID of the application handled by the forker
        :param node_uid: UID of the node hosting the forker
        :param node_name: Name of the node hosting the forker
        :param host: Address of the node
        :param port: Port to access the forker
        """
        if node_uid == self._local_uid:
            # Ignore this heart beat (sent by us)
            return

        with self._lst_lock:
            # Update the forker LST
            to_register = uid not in self._forker_lst
            self._forker_lst[uid] = time.time()

        if to_register:
            # The forker wasn't known, register it
            _logger.debug("Register forker: %s from %s/%s",
                          uid, node_uid, node_name)
            self.register_forker(uid, node_uid, node_name, host, port)


    def __lst_loop(self):
        """
        Loop that validates the LST of all forkers and removes those who took
        to long to respond
        """
        to_delete = set()

        while not self._stopped.is_set():
            with self._lst_lock:
                loop_start = time.time()

                for uid, last_seen in self._forker_lst.items():
                    if not last_seen:
                        # No LST for this forker
                        _logger.warning("Invalid LST for %s", uid)

                    elif (loop_start - last_seen) > self._forker_ttl:
                        # TTL reached
                        to_delete.add(uid)
                        _logger.info("Forker %s reached TTL.", uid)

                for uid in to_delete:
                    # Lost forkers
                    self._send_forker_lost(uid)

                # Clear the to_delete set
                to_delete.clear()

            # Wait a second or the event before next loop
            self._stopped.wait(1)


    def handle_isolate_presence(self, uid, name, node, event):
        """
        Handles an isolate presence event

        :param uid: UID of the isolate
        :param name: Name of the isolate
        :param node: Node of the isolate
        :param event: Kind of event
        """
        if event == cohorte.signals.ISOLATE_UNREGISTERED:
            # Isolate lost: remove informations about it
            with self._lst_lock:
                try:
                    del self._isolate_forker[uid]
                except KeyError:
                    pass

                try:
                    del self._forker_lst[uid]
                except:
                    pass


    @Validate
    def validate(self, context):
        """
        Component validated
        """
        # Convert port into integer
        self._port = int(self._port)

        # Get the local node UID
        self._local_uid = self._directory.get_local_node()

        # Start the event pool
        self._events_thread = pelix.threadpool.ThreadPool(1, \
                                                  logname="forker-aggregator")
        self._events_thread.start()

        # Start the multicast listener
        self._multicast = MulticastReceiver(self._group, self._port,
                                            self._handle_heartbeat)
        self._multicast.start()

        # Clear the stop event
        self._stopped.clear()

        # Start the TTL thread
        self._lst_thread = threading.Thread(target=self.__lst_loop,
                                            name="Forker-LST-loop")
        self._lst_thread.start()

        _logger.info("Forker aggregator validated on group=%s, port=%d",
                     self._group, self._port)


    @Invalidate
    def invalidate(self, context):
        """
        Component invalidated
        """
        # Stop the multicast listener
        self._multicast.stop()
        self._multicast = None

        # Set the stop event
        self._stopped.set()

        # Stop the TTL thread
        self._lst_thread.join(1)
        self._lst_thread = None

        # Unregister all forkers
        for forker in list(self._forker_lst.keys()):
            self._send_forker_lost(forker)

        # Stop the thread pool
        self._events_thread.stop()
        self._events_thread = None

        # Clear storage
        self._forker_lst.clear()
        self._isolate_forker.clear()
        self._local_uid = None

        _logger.info("Forker aggregator invalidated")
