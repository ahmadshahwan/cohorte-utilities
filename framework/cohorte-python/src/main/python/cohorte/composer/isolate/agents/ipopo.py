#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
The iPOPO composer agent

:author: Thomas Calmant
:copyright: Copyright 2013, isandlaTech
:license: GPLv3
:version: 3.0.0

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

# Module version
__version_info__ = (3, 0, 0)
__version__ = ".".join(str(x) for x in __version_info__)

# Documentation strings format
__docformat__ = "restructuredtext en"

# ------------------------------------------------------------------------------

# Composer
import cohorte.composer

# iPOPO Decorators
from pelix.ipopo.decorators import ComponentFactory, Requires, Provides, \
    Instantiate, Validate, Invalidate

# Pelix
import pelix.ipopo.constants as constants
import pelix.remote

# Standard library
import logging
import threading

# ------------------------------------------------------------------------------

_logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------

@ComponentFactory()
@Provides(cohorte.composer.SERVICE_AGENT_ISOLATE)
@Requires('_ipopo', constants.IPOPO_SERVICE_SPECIFICATION)
@Instantiate('cohorte-composer-agent-ipopo')
class IPopoAgent(object):
    """
    The iPOPO component handler for the isolate composer
    """
    def __init__(self):
        """
        Sets up members
        """
        # Injected services
        self._ipopo = None

        # Name -> Component
        self.__names = {}

        # Factory -> set(Instantiated components)
        self.__components = {}

        # Factory -> set(Remaining components)
        self.__remaining = {}

        # Thread safety
        self.__lock = threading.RLock()


    def handle_ipopo_event(self, event):
        """
        Handles an iPOPO event

        :param event: An iPOPO event
        """
        kind = event.get_kind()
        factory = event.get_factory_name()

        with self.__lock:
            if kind == constants.IPopoEvent.REGISTERED:
                # New factory registered
                try:
                    # Instantiate waiting components
                    self.handle(self.__remaining[factory])

                except KeyError:
                    # Unknown factory
                    pass

            elif kind == constants.IPopoEvent.UNREGISTERED:
                # Factory gone, put components in remaining state
                try:
                    self.__remaining.setdefault(factory, set()) \
                                        .update(self.__components.pop(factory))

                except KeyError:
                    # No instantiated components for this factory
                    pass


    @Validate
    def validate(self, _):
        """
        Component validated
        """
        # Register to iPOPO events
        self._ipopo.add_listener(self)


    @Invalidate
    def invalidate(self, _):
        """
        Component invalidated
        """
        # Unregister from iPOPO events
        self._ipopo.remove_listener(self)


    def _compute_properties(self, component):
        """
        Computes the configuration properties if the given component
        """
        # Copy existing properties
        properties = component.properties.copy()

        # TODO: prepares properties (filters...)

        # TODO: add position informations (name, node, isolate, ...)

        # Export the component interfaces
        properties.setdefault(pelix.remote.PROP_EXPORTED_INTERFACES, "*")
        return properties


    def __try_instantiate(self, component):
        """
        Tries to instantiate a component

        :param component: A component bean
        :return: True if the component has been validated, False if its factory
                 is missing
        :raise: Error instantiating the component
        """
        try:
            # Prepare properties (filters...)
            factory = component.factory
            properties = self._compute_properties(component)

            # Instantiate the component
            self._ipopo.instantiate(factory,
                                    component.name,
                                    properties)

            # Component instantiated
            try:
                remaining = self.__remaining[factory]
                remaining.discard(component)
                if not remaining:
                    del self.__remaining[factory]
            except KeyError:
                # Component wasn't a remaining one
                pass

            # Store it
            self.__components.setdefault(factory, set()).add(component)
            return True

        except TypeError:
            # Missing factory: maybe later
            _logger.warning("iPOPO agent: factory missing for %s :(", component)
            return False

        _logger.warning("iPOPO agent failed to instantiate %s :(", component)
        return False


    def handle(self, components):
        """
        Tries to instantiate the given components immediately and stores the
        remaining ones to instantiate them as soon as possible

        :param components: A set of RawComponent beans
        :return: The immediately instantiated components
        """
        with self.__lock:
            # Beans of the components to instantiate
            components = set(components)
            instantiated = set()

            for component in components:
                try:
                    # Check if component is already running
                    stored = self.__names[component.name]
                    if stored in self.__components[component.factory]:
                        # Already running
                        _logger.debug("%s is already running...",
                                      component.name)
                        continue

                    elif stored in self.__remaining[component.factory]:
                        # Already in the remaining list, use the stored bean
                        # -> this will avoid different hashes due to network
                        # transmission
                        component = stored

                except KeyError:
                    # Not yet known component
                    pass


                # Store the name
                self.__names[component.name] = component

                try:
                    # Try instantiation (updates local storage)
                    if self.__try_instantiate(component):
                        instantiated.add(component)

                    else:
                        # Factory not found, keep track of the component
                        self.__remaining.setdefault(component.factory, set()) \
                                                                .add(component)

                except Exception as ex:
                    # Other errors
                    _logger.exception("Error instantiating component %s: %s",
                                      component, ex)

            return instantiated


    def kill(self, name):
        """
        Kills the component with the given name

        :param name: Name of the component to kill
        :raise KeyError: Unknown component
        """
        with self.__lock:
            # Get the component bean
            component = self.__names.pop(name)

            # Bean storage
            storage = self.__components

            try:
                # Kill the component
                self._ipopo.kill(name)

            except ValueError:
                # iPOPO didn't know about the component,
                # remove it from the remaining ones
                storage = self.__remaining

            else:
                # Bean is stored in the instantiated components dictionary
                storage = self.__components

            try:
                # Clean up the storage
                components = storage[component.factory]
                components.remove(component)
                if not components:
                    del storage[component.factory]

            except KeyError:
                # Strange: the component is not where it is supposed to be
                _logger.warning("Component %s is not stored where it is "
                                "supposed to be (%s components)", name,
                                "instantiated" if storage is self.__components \
                                else "remaining")
                return
