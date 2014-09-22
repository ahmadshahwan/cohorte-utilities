#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
Voting engine: Approbation vote

The candidate with the most votes is elected

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

# Module version
__version_info__ = (1, 0, 0)
__version__ = ".".join(str(x) for x in __version_info__)

# Documentation strings format
__docformat__ = "restructuredtext en"

# ------------------------------------------------------------------------------

# Voting system
import cohorte.vote
import cohorte.vote.beans as beans

# iPOPO Decorators
from pelix.ipopo.decorators import ComponentFactory, Provides, Instantiate, \
    Property

# Standard library
import logging
import math

# ------------------------------------------------------------------------------

_logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------

@ComponentFactory()
@Provides(cohorte.vote.SERVICE_VOTE_ENGINE)
@Property('_kind', cohorte.vote.PROP_VOTE_KIND, 'presidentielle')
@Instantiate('vote-engine-presidentielle')
class PresidentielleFrEngine(object):
    """
    Voting system core service
    """
    def __init__(self):
        """
        Sets up members
        """
        # Supported kind of vote
        self._kind = None


    def get_kind(self):
        """
        Returns supported kind of vote
        """
        return self._kind


    def get_options(self):
        """
        Returns the options available for this engine

        :return: An option -> description dictionary
        """
        return {}


    def analyze(self, vote_round, ballots, candidates, parameters, vote_bean):
        """
        Analyzes the results of a vote

        :param vote_round: Round number (starts at 1)
        :param ballots: All ballots of the vote
        :param candidates: List of all candidates
        :param parameters: Parameters for the vote engine
        :param vote_bean: A VoteResults bean
        :return: The candidate(s) with the most votes
        """
        # Count the number of votes for each candidate
        results = {}
        for ballot in ballots:
            try:
                candidate = ballot.get_for()[0]
                if candidate in candidates:
                    # In this kind of election, we can't have additional
                    # candidates
                    results[candidate] = results.get(candidate, 0) + 1

            except IndexError:
                # Blank vote
                continue

        # Store the results
        results = vote_bean.set_results(results)

        # Compute the number of votes for absolute majority
        nb_votes = sum(result[0] for result in results)
        majority = math.floor(nb_votes / 2) + 1

        if results[0][0] >= majority:
            # We have a winner
            return results[0][1]

        else:
            # We need a new round, with the two best candidates
            raise beans.NextRound(result[1] for result in results[:2])
