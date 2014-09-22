#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
Forker multicast heartbeat listener.

:author: Thomas Calmant
:license: GPLv3
"""

# Documentation strings format
__docformat__ = "restructuredtext en"

# Boot module version
__version__ = "1.0.0"

# ------------------------------------------------------------------------------

# COHORTE
import cohorte.forker
import cohorte.signals

# Multicast utility module
import cohorte.utils.multicast as multicast

# Pelix/iPOPO
from pelix.ipopo.decorators import ComponentFactory, Requires, Validate, \
    Invalidate, Property, Provides
from pelix.utilities import to_bytes, to_unicode
import pelix.http

# ------------------------------------------------------------------------------

# Standard library
import logging
import select
import struct
import threading
import time

# ------------------------------------------------------------------------------

# Heart beat packet type
PACKET_TYPE_HEARTBEAT = 1

_logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------

def make_heartbeat(port, application_id, isolate_id, node_id, node_name):
    """
    Prepares the heart beat UDP packet

    Format : Little endian
    * Packet type (1 byte)
    * Signals port (2 bytes)
    * Application ID length (2 bytes)
    * application_id (variable, UTF-8)
    * Isolate ID length (2 bytes)
    * Isolate ID (variable, UTF-8)
    * Node UID length (2 bytes)
    * Node UID (variable, UTF-8)
    * Node name length length (2 bytes)
    * Node name (variable, UTF-8)

    :param port: The Signals access port
    :param application_id: The ID of the current application
    :param isolate_id: The ID of this isolate
    :param node_id: The host node ID
    :param node_name: The host node name
    :return: The heart beat packet content (byte array)
    """
    # Type and port...
    packet = struct.pack("<BH", PACKET_TYPE_HEARTBEAT, port)

    for string in (application_id, isolate_id, node_id, node_name):
        # Strings...
        string_bytes = to_bytes(string)
        packet += struct.pack("<H", len(string_bytes))
        packet += string_bytes

    return packet

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
        self._socket, self._group = multicast.create_multicast_socket(
            self._group, self._port)

        # Start the listening thread
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self.__read,
            name="MulticastReceiver-{0}".format(self._port))
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

@ComponentFactory("cohorte-forker-heartbeat-multicast-factory")
@Provides(cohorte.signals.SERVICE_ISOLATE_PRESENCE_LISTENER)
@Requires('_discovery', cohorte.forker.SERVICE_DISCOVERY)
@Requires('_forker', cohorte.SERVICE_FORKER)
@Requires('_http', pelix.http.HTTP_SERVICE)
@Property('_group', 'multicast.group', '239.0.0.1')
@Property('_port', 'multicast.port', 42000)
@Property('_forker_ttl', 'forker.ttl', 5)
class MulticastHeartbeat(object):
    """
    Multicast heartbeats handler
    """
    def __init__(self):
        """
        Sets up the component
        """
        # Injected services
        self._discovery = None
        self._forker = None
        self._http = None

        # Local information
        self._context = None
        self._local_uid = None

        # Properties
        self._group = "239.0.0.1"
        self._port = 42000
        self._forker_ttl = 10

        # Multicast receiver
        self._multicast_recv = None

        # Multicast sender
        self._multicast_send = None
        self._multicast_target = None

        # Threads
        self._stop_event = threading.Event()
        self._lst_thread = None
        self._heart_thread = None

        # Forker UID -> Last Time Seen
        self._forker_lst = {}
        self._lst_lock = threading.RLock()


    @Validate
    def _validate(self, context):
        """
        Component validated
        """
        self._context = context
        self._port = int(self._port)

        # Get the local forker UID
        self._local_uid = self._discovery.get_uid()

        # Start the multicast listener
        self._multicast_recv = MulticastReceiver(self._group, self._port,
                                                 self.handle_heartbeat)
        self._multicast_recv.start()

        # Create the multicast sender socket
        self._multicast_send, address = multicast.create_multicast_socket(
            self._group, self._port, False)

        # Store group information
        self._multicast_target = (address, self._port)

        # Clear the stop event
        self._stop_event.clear()

        # Start the heart
        self._heart_thread = threading.Thread(target=self.__heart_loop,
                                              name="Forker-HeartBeat")
        self._heart_thread.start()

        # Start the TTL thread
        self._lst_thread = threading.Thread(target=self.__lst_loop,
                                            name="Forker-LST-loop")
        self._lst_thread.start()

        _logger.info("Forker multicast heartbeat validated on group=%s, "
                     "port=%d", self._group, self._port)


    @Invalidate
    def _invalidate(self, context):
        """
        Component invalidated
        """
        # Set the stop event
        self._stop_event.set()

        # Stop the multicast listener
        self._multicast_recv.stop()
        self._multicast_recv = None

        # Wait for the thread to stop
        self._heart_thread.join(.5)

        # Wait for the TTL thread
        self._lst_thread.join(.5)
        self._lst_thread = None

        # Clear the multicast sender
        self._multicast_send.close()
        self._multicast_send = None
        self._multicast_target = None

        # Clear storage
        self._forker_lst.clear()
        self._local_uid = None
        self._context = None

        _logger.info("Forker multicast discovery invalidated")


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
                    del self._forker_lst[uid]
                except:
                    pass


    def handle_heartbeat(self, uid, application_id, node_uid, node_name,
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
        if uid == self._local_uid:
            # Ignore this heart beat (sent by us)
            return

        if application_id != self._discovery.get_appid():
            # Forker from another application: ignore
            return

        with self._lst_lock:
            # Update the forker LST
            to_register = uid not in self._forker_lst
            self._forker_lst[uid] = time.time()

        if to_register:
            # The forker wasn't known, register it
            self._discovery.register_forker(uid, node_uid, node_name,
                                            host, port)


    def __heart_loop(self):
        """
        Loop sending heart beats every 3 seconds
        """
        # Prepare the packet
        beat = make_heartbeat(
            self._http.get_access()[1],
            self._discovery.get_appid(),
            self._discovery.get_uid(),
            self._context.get_property(cohorte.PROP_NODE_UID),
            self._context.get_property(cohorte.PROP_NODE_NAME))

        while not self._stop_event.is_set() and self._forker.is_alive():
            # Send the heart beat using the multicast socket
            self._multicast_send.sendto(beat, 0, self._multicast_target)

            # Wait 3 seconds before next loop
            self._stop_event.wait(3)


    def __lst_loop(self):
        """
        Loop that validates the LST of all forkers and removes those who took
        to long to respond
        """
        to_delete = set()

        while not self._stop_event.is_set():
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
                    # Notify the ForkerDiscovery of lost forkers
                    self._forker_timeout(uid)

                # Clear the to_delete set
                to_delete.clear()

            # Wait a second or the event before next loop
            self._stop_event.wait(1)


    def _forker_timeout(self, uid):
        """
        Sends a "forker lost" signal

        :param uid: UID of the lost forker
        """
        # Remove the references to the forker in the LST
        with self._lst_lock:
            if uid in self._forker_lst:
                del self._forker_lst[uid]

        # Call the forker discovery core
        self._discovery.forker_lost(uid,
                                    "Forker multicast heartbeat timed out.")
