##///////////////////////////////////////////////////////////////////////
##
## (c) University of Southampton IT Innovation Centre, 2021
##
## Copyright in this software belongs to University of Southampton
## IT Innovation Centre of Gamma House, Enterprise Road,
## Chilworth Science Park, Southampton, SO16 7NS, UK.
##
## This software may not be used, sold, licensed, transferred, copied
## or reproduced in whole or in part in any manner or form or in or
## on any media by any person other than in accordance with the terms
## of the Licence Agreement supplied with the software, or otherwise
## without the prior written consent of the copyright owners.
##
## This software is distributed WITHOUT ANY WARRANTY, without even the
## implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
## PURPOSE, except where stated in the Licence Agreement supplied with
## the software.
##
##      Created By :            Panos Melas
##      Created Date :          2022-02-07
##      Created for Project :   xxx
##
##///////////////////////////////////////////////////////////////////////

import re
#import textwrap
from collections import defaultdict
import logging
import boolean

from ssm_api_client.models.control_set import ControlSet

from app.ssm.cyberkit4sme.shortest_path_graph import plot_graph

#logging.basicConfig(level=logging.DEBUG, format='%(process)d-%(levelname)s-%(message)s')
#logger = logging.getLogger(__name__)

from fastapi.logger import logger

INFINITY = 99999999
NODE_COUNTER = 0

algebra = boolean.BooleanAlgebra()
TRUE, FALSE, NOT, AND, OR, symbol = algebra.definition()

DUMMY_CSG = "dummy-csg"

URI_PREFIX = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/"


class ShortestPathDataset:
    """ Attack path class (fast version)"""

    def __init__(self, dynamic_model, full_model):
        self.dynamic = dynamic_model
        self.full = full_model
        self.threats = full_model['threats']
        self.assets = full_model['assets']
        self.cs_dict = full_model['control_sets']
        self.csg_dict = full_model['csg_sets']

        self.prepare()
        self.csg_counter = 0
        self.csg_counter_out = 0

    def prepare(self):
        """ Prepare data strucutes for ThreatTree/Nodes """

        logger.info("preparing attack path datasets...")

        logger.debug(f"-" * 80)
        logger.debug(f"Dynamic threats:       {len(self.dynamic.threats)}")
        logger.debug(f"Static threats :       {len(self.threats)}")
        logger.debug(f"Dynamic misbehaviours: {len(self.dynamic.misbehaviour_sets)}")
        logger.debug(f"CSGs :                 {len(self.csg_dict)}")
        logger.debug(f"CSs :                  {len(self.cs_dict)}")

        for threat in self.threats:
            if not threat in self.dynamic.threats:
                logger.debug(f"Threat {threat} not found in dynamic")

        for threat in self.dynamic.threats:
            if not threat in self.threats:
                logger.debug(f"Threat {threat} not found in static")

        # build CSGs dictionary from full model
        #self.csg_dict = {}
        self.threat_to_csg = defaultdict(list)
        for threat in self.threats.values():
            #self.threat_to_csg[threat.uri[60:]] = list(threat.control_strategies.values())
            self.threat_to_csg[threat.uri[60:]] = threat.control_strategies
            continue
            #TODO remove the following block
            for csg in threat.control_strategies.values():
                short_uri = csg.uri[60:]
                if short_uri not in self.csg_dict:
                    self.csg_dict[short_uri] = csg

        #TODO no need for this statement
        logger.debug(f"CSGs found: {len(self.csg_dict)}")

        # root causes
        self.root_causes = {x.uri for x in self.dynamic.threats.values() if x.root_cause}
        logger.debug(f"root causes threats:   {len(self.root_causes)}")

        # likelihood dict for threats and misbehavours
        self.likelihood = {}
        self.likelihood_label = {}
        for k, v in self.dynamic.threats.items():
            if not v.likelihood:
                self.likelihood[k] = -1
                self.likelihood_label[k] = None
            else:
                self.likelihood[k] = self.dynamic.levels['liLevels'][v.likelihood].level_value
                self.likelihood_label[k] = self.dynamic.levels['liLevels'][v.likelihood].label

        for k, v in self.dynamic.misbehaviour_sets.items():
            if not v.likelihood:
                self.likelihood[k] = -1
                self.likelihood_label[k] = None
            else:
                self.likelihood[k] = self.dynamic.levels['liLevels'][v.likelihood].level_value
                self.likelihood_label[k] = self.dynamic.levels['liLevels'][v.likelihood].label
        logger.debug(f"likelihood set: {len(self.likelihood)}")

        # normal ops
        self.normal_ops = set()
        for threat in self.dynamic.threats.values():
            if threat.normal_operation:
                self.normal_ops.add(threat.uri)
        logger.info(f"Finding real and 'normal operation' root causes..."
                    f"{len(self.root_causes)}:{len(self.normal_ops)}")

        self.miss_sets = set()
        for ms_key, ms in self.dynamic.misbehaviour_sets.items():
            self.miss_sets.add(ms_key)
            if ms.normal_op_effect:
                self.normal_ops.add(ms_key)

            if ms.external_cause:
                self.normal_ops.add(ms_key)
            for threat in self.dynamic.threats.values():
                if ms_key in threat.direct_misbehaviours:
                    if threat.uri in self.normal_ops:
                        self.normal_ops.add(ms_key)

        for twa_key, twa_value in self.dynamic.twas.items():
            if twa_value.external_cause:
                self.normal_ops.add(twa_key)

        logger.info(f"Finding real and 'normal operation' root causes partIIa..."
                    f"{len(self.root_causes)}:{len(self.normal_ops)}")


        # print datasets stats
        logger.debug(f"="*80)
        logger.debug(f"Finding all assets: {len(self.assets)}")
        logger.debug(f"Finding all threats (normal ops): {len(self.dynamic.threats)}, ({len(self.normal_ops)})")
        logger.debug(f"Finding misbehaviour sets: {len(self.dynamic.misbehaviour_sets)}")
        logger.debug(f"Root causes {len(self.root_causes)}")
        logger.debug(f"normal ops {len(self.normal_ops)}")
        logger.debug(f"assets {len(self.assets)}")
        logger.debug(f"likelihood {len(self.likelihood)}")

    #TODO not used?
    def get_misbehaviour_parent_uris(self, misb_uri):
        """ find threats causing misbehaviour """
        parent_uris = []
        for threat in self.dynamic.threats.values():
            if misb_uri in threat.direct_misbehaviours:
                parent_uris.append(threat.uri)
        return parent_uris

    def get_misbehaviour_direct_cause_uris(self, misb_uri):
        """ find threats causing misbehaviour """
        parent_uris = []
        for threat in self.dynamic.threats.values():
            if misb_uri in threat.direct_misbehaviours:
                parent_uris.append(threat.uri)

        return parent_uris

    def get_threat_direct_cause_uris(self, threat_uri):
        """ find MS caused by threat """
        direct_cause_uris = []
        for ms_key, ms_value in self.dynamic.misbehaviour_sets.items():
            if threat_uri in ms_value.caused_threats:
                direct_cause_uris.append(ms_key)

        for twa_key, twa_value in self.dynamic.twas.items():
            if threat_uri in twa_value.caused_threats:
                direct_cause_uris.append(twa_key)

        #direct_cause_uris += self.dynamic.threats[threat_uri].entry_points
        return direct_cause_uris

    #TODO not used?
    def get_threat_parent_uris(self, threat_uri):
        """ find MS caused by threat """
        parent_uris = []
        for ms_key, ms_value in self.dynamic.misbehaviour_sets.items():
            if threat_uri in ms_value.caused_threats:
                parent_uris.append(ms_key)
        return parent_uris

    def get_control_strategy_uris(self, threat_uri):
        csgs = []
        for csg in self.static['threats'][threat_uri]['controlStrategies']:
            csgs.append(csg)
        return csgs

    def is_runtime_changable(self, csg_uri):
        return not re.search(r'\b-Implementation-Runtime\b|\b-Implementation\b', csg_uri) \
               and (csg_uri.find("-Runtime") != -1 or csg_uri.find("-Implementation") != -1)

    def check_implementation_runtime(self, csg_uri):
        pattern = re.compile(r'\b-Implementation-Runtime\b|\b-Implementation\b')
        return bool(pattern.search(csg_uri))

    def has_external_dependencies(self, csg_uri):
        return not (csg_uri.find("-Implementation-Runtime") != -1 or csg_uri.find("-Implementation") != -1)

    def is_contingency_activation(self, csg_uri):
        """ check if there is a contigency plan """
        if self.has_external_dependencies(csg_uri):
            contingency_plan = re.sub(r'-Implementation-Runtime|-Implementation', '', csg_uri)
        else:
            return False

        if contingency_plan in self.csg_dict:
            activated = True
            controls = self.csg_dict[contingency_plan].mandatory_cs + self.csg_dict[contingency_plan].optional_cs
            for cs_uri in controls:
                cs = self.cs_dict[cs_uri]
                if not cs.proposed:
                    activated = False
                    break
            return activated
        return True

    def get_threat_control_strategy_uris(self, threat_uri, future=True):
        """Return list of control strategies (urirefs) that block a threat (uriref)"""

        # "blocks": means a CSG appropriate for current or future risk calc
        # "mitigates": means a CSG appropriate for future risk (often a
        # contingency plan for a current risk CSG); excluded from likelihood
        # calc in current risk

        csg_uris = []

        if future:
            for csg_uri_long, csg_type in self.threat_to_csg[threat_uri].items():
                csg_uri = csg_uri_long[60:]
                if csg_type in ["BLOCK", "MITIGATE"]:
                    if self.has_external_dependencies(csg_uri):
                        description = self.csg_dict[csg_uri].description
                        # TODO: eventually need to remove this hack and just append the csg_uri
                        csg_uris.append(MyControlStrategy.get_or_create_csg(csg_uri, description))
        else:
            for csg_uri_long, csg_type in self.threat_to_csg[threat_uri].items():
                csg_uri = csg_uri_long[60:]
                if csg_type == "BLOCK":
                    if self.is_runtime_changable(csg_uri):
                        if not self.is_contingency_activation(csg_uri):
                            description = self.csg_dict[csg_uri].description
                            # TODO: eventually need to remove this hack and just append the csg_uri
                            csg_uris.append(MyControlStrategy.get_or_create_csg(csg_uri, description))
                            self.csg_counter += 1
                        else:
                            logger.debug(f"EXCLUDED CSG: {csg_uri}, {threat_uri}")
                            self.csg_counter_out += 1
        return csg_uris

    def get_csg_control_set_uris(self, csg_uri):
        if isinstance(csg_uri, MyControlStrategy):
            csg_uri = csg_uri.original_uriref
        css = []
        controls = self.csg_dict[csg_uri].mandatory_cs + self.csg_dict[csg_uri].optional_cs
        for cs_uri in controls:
            css.append(self.cs_dict[cs_uri])
        return css

    def get_csg_inactive_control_set_uris(self, csg_uri):
        css = []
        if isinstance(csg_uri, MyControlStrategy):
            csg_uri = csg_uri.original_uriref
        csg = self.csg_dict[csg_uri]
        controls = csg.mandatory_cs + csg.optional_cs
        for cs_uri in controls:
            if not self.cs_dict[cs_uri].proposed:
                css.append(cs_uri)
        return css

    def get_threat_inactive_control_strategies(self, threat_uri, future_risk=True):
        csg_uris = []
        for csg_uri in self.get_threat_control_strategy_uris(threat_uri, future_risk):
            cs_uris = self.get_csg_inactive_control_set_uris(csg_uri)
            if len(cs_uris) > 0:
                csg_uris.append(csg_uri)
        return csg_uris


class ThreatTree():
    """The container for a set of TreeNodes"""
    def __init__(self, target_uris=None, is_future_risk=True, shortest_path=False, apd_obj=None):
        """
        Parameters
        ----------
        target_uris : list of URIRef
            describes the misbehaviours that we want to know the threat trees for
        is_future_risk : bool, optional
            whether to do a future or current risk analysis (affects which control strategies are considered)
        shortest_path : bool, optional
            if True then only the TreeNodes on the shortest paths are included in the ThreatTree
        """
        self._apd = apd_obj
        self._node_by_uri = {}
        self.target_uris = target_uris
        self.is_future_risk = is_future_risk
        self.bounding_urirefs = None
        self.node_counter = 0
        if not shortest_path:
            logging.info(f"Running backtrace for {target_uris}")
            self._backtrace(compute_logic=True)
            logging.info("Tree has " + str(len(self.nodes)) + " nodes")
        else:
            # If the shortest path is required then we get the URIRefs of the shortest path nodes from the first pass at the ThreatTree
            # then discard all TreeNodes and create a new ThreatTree which is bounded by the shortest path URIRefs.
            logging.info(f"Running first backtrace for {target_uris}")
            self._backtrace(compute_logic=False)
            logging.info("Tree has " + str(len(self.nodes)) + " nodes")
            self.bounding_urirefs = set([node.uri for node in self.shortest_path_nodes])
            self._node_by_uri = {}
            logging.info("Running second backtrace, bounded by " + str(len(self.bounding_urirefs)) + " nodes")
            self.node_counter = 0
            self._backtrace(compute_logic=True)
            logging.info("Tree has " + str(len(self.nodes)) + " nodes")


    def __getitem__(self, uri):
        return self._node_by_uri[uri]

    def get_or_create_node(self, uri):
        if uri not in self._node_by_uri:
            self.node_counter += 1
            self._node_by_uri[uri] = TreeNode(uri, self._apd, self, self.node_counter)
        return self._node_by_uri[uri]

    def _backtrace(self, compute_logic=True):
        for target_uri in self.target_uris:
            node = self.get_or_create_node(target_uri)
            node.is_target_ms = True
            logging.info("Making tree node for " + str(node.uri))
            node.backtrace(compute_logic=compute_logic)

    def get_dummy_uriref(self, dummy_uri):
        csg_uri = MyControlStrategy.get_by_dummy_uriref(dummy_uri)
        return csg_uri.original_uriref

    @property
    def nodes(self):
        # Don't return the nodes that are in the error state
        return [node for node in self._node_by_uri.values() if not node.not_a_cause]

    @property
    def uris(self):
        # Don't return the nodes that are in the error state
        return [uri for uri in self._node_by_uri.keys() if not self._node_by_uri[uri].not_a_cause]

    @property
    def root_causes(self):
        uris = set()
        for node in self.nodes:  # Using property
            if node.is_root_cause:
                uris.add(node.uri)
        return uris

    @property
    def external_causes(self):
        uris = set()
        for node in self.nodes:
            if node.is_external_cause:
                uris.add(node.uri)
        return uris

    @property
    def initial_causes(self):
        uris = set()
        for node in self.nodes:
            if node.is_initial_cause:
                uris.add(node.uri)
        return uris

    @property
    def normal_operations(self):
        uris = set()
        for node in self.nodes:
            if node.is_normal_op:
                uris.add(node.uri)
        return uris

    def add_max_distance_from_target(self, uriref, current_path=None):
        """Find the maximum distance from a target URI (useful to space out nodes for plotting)."""
        if current_path == None:
            current_path = ()
        # Using a tuple for current_path to ensure that when we change it we make a copy so that the addition is undone when the recursion unwinds
        current_path = current_path + (uriref,)
        current_node = self._node_by_uri[uriref]
        target_uriref = current_path[0]
        current_distance = current_node.max_distance_from_target_by_target.get(target_uriref, -1)
        current_node.max_distance_from_target_by_target[target_uriref] = max(current_distance, len(current_path) - 1)  # start at 0
        for cause_uriref in current_node.direct_cause_uris:
            # there can be loops in the "tree" so have to make sure we don't follow one
            if cause_uriref not in current_path:
                self.add_max_distance_from_target(cause_uriref, current_path)

    # def get_nodes_in_target_tree(self, target_uriref):
        #TODO: filter self.nodes to find those where max_distance_from_target_by_target has target_uriref as a key

    @property
    def shortest_path_nodes(self):
        """Return the set of nodes that are on the shortest path(s)."""
        # The strategy is to remove nodes where all the children are NOT further away from the root cause, or where there are no children.
        # We define "good nodes" to be ones which have at least one child further away than the node, remove the others and iterate until no change.
        short_path_nodes = set(self.nodes)
        while True:
            good_nodes = set([self._node_by_uri[target_ms_uri] for target_ms_uri in self.target_uris])
            for node in short_path_nodes:
                for cause_uri in node.direct_cause_uris:
                    cause_node = self._node_by_uri[cause_uri]
                    # Special logic here to still include normal-ops as their root cause distances are measured from a normal-op initial cause so at the boundary the normal logic fails.
                    if (cause_node.min_distance_from_root < node.min_distance_from_root) or (cause_node.is_normal_op and not node.is_normal_op):
                        good_nodes.add(cause_node)
            if len(good_nodes & short_path_nodes) < len(short_path_nodes):
                short_path_nodes = good_nodes & short_path_nodes
            else:
                break
        return short_path_nodes


    @property
    def attack_mitigation_csg(self):
        return LogicalExpression(self._apd, [self[uri].attack_tree_mitigation_csg for uri in self.target_uris], all_required=True)

    @property
    def attack_mitigation_cs(self):
        return LogicalExpression(self._apd, [self[uri].attack_tree_mitigation_cs for uri in self.target_uris], all_required=True)

    @property
    def threat_graph_mitigation_csg(self):
        return LogicalExpression([self[uri].threat_tree_mitigation_csg for uri in self.target_uris], all_required=True)

    @property
    def threat_graph_mitigation_cs(self):
        return LogicalExpression([self[uri].threat_tree_mitigation_cs for uri in self.target_uris], all_required=True)

    def stats(self):
        # calculate some tree stats - not important
        node_uris = set(self.uris)

        logger.debug(f"ThreatTree nodes:      {len(self._node_by_uri)}")
        logger.debug(f"ThreatTree uris (set): {len(set(self.uris))}")

        csgs = set()
        controls = set()
        spn_counter = 0
        for node in self.shortest_path_nodes:
            if node.is_threat:
                spn_counter += 1
                for csg_uri in self._apd.threat_to_csg[node.uri]:
                    csgs.add(csg_uri[60:])
                    #for cs_uri in self._apd.csg_dict[csg_uri[60:]].control_sets:
                    csg_controls = self._apd.csg_dict[csg_uri[60:]].mandatory_cs + self._apd.csg_dict[csg_uri[60:]].optional_cs
                    for cs_uri in csg_controls:
                        controls.add(cs_uri)

        logger.debug(f"Shortest path nodes: {spn_counter}")
        logger.debug(f"CSGs: {len(csgs)}")
        logger.debug(f"CS: {len(controls)}")

        sorted_nodes = sorted(self.nodes, key=lambda x: x.min_distance_from_root, reverse=True)
        nodes_dist_freq = defaultdict(int)
        for node in sorted_nodes:
            nodes_dist_freq[node.min_distance_from_root] += 1
        logger.debug(f"Frequencies: {nodes_dist_freq}")
        # end calculate some stats - not important

    def parse_and_plot_tree_nodes(self, rec_id=1, label:str='', output_format:str='svg'):
        logger.debug("parsing tree nodes")

        logger.debug(f"shortest path nodes: {len(self.shortest_path_nodes)}")
        external_causes = [node for node in self.shortest_path_nodes if node.is_external_cause]
        logger.debug(f"external causes: {len(external_causes)}")
        attack_tree_nodes = set([node for node in self.shortest_path_nodes if not node.is_normal_op])
        logger.debug(f"attack tree nodes: {len(attack_tree_nodes)}")

        self.create_links()

        self.rank_by_uri = {}

        highlighted_nodes = set(self.shortest_path_nodes)

        csgs = [csg_uri for csg_uri in self.attack_mitigation_csg.uris]

        for ms_uri in self.target_uris:
            self.set_rank(ms_uri, 0)

        for uri in self.rank_by_uri:
            self.rank_by_uri[uri] = max(self.rank_by_uri[uri])

        external_causes = [node for node in self.shortest_path_nodes if node.is_external_cause]
        attack_tree_nodes = set([node for node in self.shortest_path_nodes if not node.is_normal_op])
        for node in external_causes:
            for effect_uri in node.direct_effect_uris:
                effect = self._node_by_uri[effect_uri]
                if effect in attack_tree_nodes:
                    attack_tree_nodes.add(node)

        logger.debug(f"NODES TO PLOT: {len(self.shortest_path_nodes)}")
        logger.debug(f"LINKS TO PLOT: {len(self.links)}")
        logger.debug(f"HIGHLIGHTED NODES: {len(highlighted_nodes)}")

        #nodes = set([self._node_by_uri[uri] for uri in self.rank_by_uri])

        logger.debug(f"shortest mitigation csgs: {len(self.attack_mitigation_csg.uris)}")
        logger.debug(f"Threat tree nodes: {len(self.shortest_path_nodes)}")
        logger.debug(f"Attack path nodes: {len(attack_tree_nodes)}")
        logger.debug(f"Highlighted nodes: {len(highlighted_nodes)}")

        if label:
            graph_label = label
        else:
            graph_label = f"graph_rec_{rec_id}.gv"

        graph = plot_graph(graph_label, attack_tree_nodes, self.links, self.rank_by_uri, highlighted_nodes, output_format)
        return graph

    def create_links(self):
        # create linsk between the nodes of the tree using appropriate
        # predicates
        self.links = set()
        for node in self.shortest_path_nodes:
            for effect_uri in node.direct_effect_uris:
                effect_node = self._node_by_uri[effect_uri]
                if node.is_threat:
                    predicate = "causes"
                else:
                    if effect_node.is_secondary_threat:
                        predicate = "causes"
                    else:
                        predicate = "enables"
                self.links.add((node, predicate, effect_node))
        logger.debug(f"Links: {len(self.links)}")

    def set_rank(self, node_uri, rank):
        if node_uri in self.rank_by_uri:
            ranks = self.rank_by_uri[node_uri]
        else:
            ranks = set()
            self.rank_by_uri[node_uri] = ranks
        if rank in ranks:
            return
        else:
            ranks.add(rank)
            for cause_uri in self._node_by_uri[node_uri].direct_cause_uris:
                self.set_rank(cause_uri, rank + 1)


class MyControlStrategy():

    object_by_description = {}
    object_by_dummy_uriref = {}

    def __init__(self, description, original_uriref, dummy_uriref):
        self.description = description
        self.original_uriref = original_uriref
        self.uriref = dummy_uriref
        # TODO: grabbing the CSG label from the end of the URI here. Really it might be better to grab it from the domain model instead. However, the domain model does have some duplication of labels (or at least could) whereas the URI ends must be unique
        self.label = un_camel_case(original_uriref.split('CSG-')[1])
        #self.inactive_control_set_uris = apdg.get_csg_inactive_control_set_uris(original_uriref)

    @classmethod
    def get_or_create_csg(cls, original_uriref, description):
        #description = str(graph.value(original_uriref, HAS_COMMENT))
        if description in cls.object_by_description:
            return cls.object_by_description[description]
        else:
            dummy_uriref = 'system#' + DUMMY_CSG + "-" + str(len(MyControlStrategy.object_by_description))
            cs = MyControlStrategy(description, original_uriref, dummy_uriref)
            cls.object_by_description[description] = cs
            cls.object_by_dummy_uriref[dummy_uriref] = cs
            return cs

    @classmethod
    def get_by_dummy_uriref(cls, dummy_uriref):
        if not dummy_uriref.startswith("system#"):
            dummy_uriref = "system#"+dummy_uriref
        return cls.object_by_dummy_uriref[dummy_uriref]

    @classmethod
    def get_by_dummy_uriref_d(cls, dummy_uriref):
        uri = str(dummy_uriref.group()[8:-2])
        if not uri.startswith("system#"):
            uri = "system#"+uri
        return cls.object_by_dummy_uriref[uri].original_uriref

class TreeNode():
    """Represents a Threat or a Misbehaviour. Could really do with having those as subclasses."""

    def __init__(self, uri, apd, nodes, counter):
        self._apd = apd
        self.uri = uri
        self.nodes = nodes  # collection it belongs to
        self.is_target_ms = False
        self.id = counter

        #self.id = apd.uri_to_id[uri]
        self.control_strategies = self._get_control_strategies()
        self.controls = self._get_controls()
        self.uri_symbol = self._make_symbol(self.uri)

        # this is all the direct causes
        all_direct_cause_uris = self._get_all_direct_cause_uris()
        # if the containing ThreatTree defines a bound on the nodes to explore then we apply it here by discarding parents not in the bounding_urirefs set
        if self.nodes.bounding_urirefs is not None:
            self.all_direct_cause_uris = set(all_direct_cause_uris) & self.nodes.bounding_urirefs
        else:
            self.all_direct_cause_uris = set(all_direct_cause_uris)

        # these represent the causes/effects which are part of the attack tree this Node is a member of:
        self.direct_cause_uris = set()
        self.direct_effect_uris = set()

        self.max_distance_from_root_by_cause = {}  # keyed by root cause logical expression
        self.min_distance_from_root_by_cause = {}  # keyed by root cause logical expression
        self.max_distance_from_target_by_target = {}  # keyed by target MS

        # LogicalExpressions to record the tree data:
        self.attack_tree_mitigation_cs = None
        self.threat_tree_mitigation_cs = None
        self.attack_tree_mitigation_csg = None
        self.threat_tree_mitigation_csg = None
        self.attack_tree = None
        self.threat_tree = None
        self.root_cause = None

        self.cannot_be_caused = False  # Flag for nodes that cannot be caused because they cause themselves
        self.not_a_cause = True  # Assume the node is not a cause no matter what path taken, unless we find otherwise

        # counters to see what's going on with the caching:
        self.visits = 0
        self.cache_hit_visits = 0
        self.cause_visits = 0
        self.no_cause_visits = 0

        # cached results:
        self.cause_results = []
        self.no_cause_results = []

    def __str__(self):
        return "TreeNode: {}\n  ID: {}\n  Comment: {}\n  {} direct causes, {} direct effects".format(
            str(self.uri), id(self), self.comment, len(self.direct_cause_uris), len(self.direct_effect_uris))

    @property
    def likelihood(self):
        return self._apd.likelihood[self.uri]

    def likelihood_text(self):
        return self._apd.likelihood_label[self.uri]

    @property
    def is_normal_op(self):
        return self.uri in self._apd.normal_ops

    @property
    def is_root_cause(self):
        return self.uri in self._apd.root_causes

    @property
    def is_threat(self):
        return self.uri in self._apd.dynamic.threats

    @property
    def is_secondary_threat(self):
        if self._apd.dynamic.threats[self.uri].secondary_effect_conditions:
            return True
        else:
            return False

    @property
    def is_initial_cause(self):
        return get_is_initial_cause(self.uri)

    @property
    def is_misbehaviour_set(self):
        return get_is_misbehaviour_set(self.uri)


    @property
    def is_external_cause(self):
        if self.uri in self._apd.dynamic.misbehaviour_sets:
            if self._apd.dynamic.misbehaviour_sets[self.uri].external_cause:
                return True
        elif self.uri in self._apd.dynamic.twas:
            if self._apd.dynamic.twas[self.uri]:
                return True
        return False

    @property
    def comment1(self):
        if self.is_threat:
            comment = self._apd.dynamic.threats[self.uri].description
            quote_counter = 0
            char_index = 0
            # need to deal with the case where there is a colon in a quoted asset label
            while (comment[char_index] != ":" or quote_counter % 2 != 0):
                if comment[char_index] == '"':
                    quote_counter += 1
                char_index += 1
            comment = comment[0:char_index]
        else:
            ms = self._apd.dynamic.misbehaviour_sets[self.uri]
            likelihood = un_camel_case(ms.prior[17:])
            label = ms.label
            comment_parts = label.split('-', 2)  # e.g. MS-LossOfConfidentiality-SourceCode
            if len(comment_parts) > 2:
                asset = comment_parts[2]
                if "LossOf" in comment_parts[1] or "Not" in comment_parts[1]:
                    aspect = un_camel_case(comment_parts[1][6:])
                    if "LossOf" in comment_parts[1]:
                        consequence = "loses"
                    else:
                        consequence = "is not"
                    return '{} likelihood that "{}" {} {}'.format(likelihood, asset, consequence, aspect).replace("\\", "")
                comment = un_camel_case(comment_parts[1]) + ' at "' + un_camel_case(comment_parts[2]) + '"'

            else:
                asset = self._apd.assets[ms.located_at].label
                if "LossOf" in comment_parts[0] or "Not" in comment_parts[0]:
                    aspect = un_camel_case(comment_parts[0][6:])
                    if "LossOf" in comment_parts[0]:
                        consequence = "loses"
                    else:
                        consequence = "is not"
                    return '{} likelihood that "{}" {} {}'.format(likelihood, asset, consequence, aspect).replace("\\", "")
                else:
                    comment = un_camel_case(comment_parts[0])
                    return '{} likelihood of "{}" {}'.format(likelihood, asset, comment).replace("\\", "")

        return comment.replace("\\", "")

    def _add_spaces(self, input_str: str):
        result = ""
        for i, c in enumerate(input_str):
            if i > 0 and c.isupper():
                result += " "
            result += c
        return result

    @property
    def comment(self):
        if self.is_threat:
            comment = self._apd.dynamic.threats[self.uri].description
            quote_counter = 0
            char_index = 0
            # need to deal with the case where there is a colon in a quoted asset label
            while (comment[char_index] != ":" or quote_counter % 2 != 0):
                if comment[char_index] == '"':
                    quote_counter += 1
                char_index += 1
            comment = comment[0:char_index]
        elif not self.uri in self._apd.dynamic.misbehaviour_sets:
            logger.debug(f"dealing with TWA(?) {self.uri}")
            twa = self._apd.dynamic.twas[self.uri]
            asset = self._apd.assets[twa.located_at].label
            if twa.asserted_level:
                level = self._apd.dynamic.levels['twLevels'][twa.asserted_level].label
            else:
                level = self._apd.dynamic.levels['twLevels'][twa.inferred_level].label
            label = self.uri.split("-")[1][:-2]
            label = self._add_spaces(label)
            return f"TWA {label} Trustworthiness of {asset} is {level}"
        else:
            ms = self._apd.dynamic.misbehaviour_sets[self.uri]
            likelihood = un_camel_case(ms.likelihood[17:])
            asset = self._apd.assets[ms.located_at].label
            label = self._apd.dynamic.misbehaviours[ms.misbehaviour].label
            comment_parts = label.split('-', 2)  # e.g. MS-LossOfConfidentiality-SourceCode
            if len(comment_parts) > 2:
                consequence = comment_parts[1]
            else:
                # has the label generation changed? A MS label seems to just be
                # the M now
                consequence = comment_parts[0]
            if "LossOf" in consequence or "Not" in consequence:
                    aspect = un_camel_case(consequence[6:])
                    if "LossOf" in consequence:
                        consequence = "loses"
                    else:
                        consequence = "is not"
                    return '{} likelihood that "{}" {} {}'.format(likelihood, asset, consequence, aspect).replace("\\", "")
            else:
                    comment = un_camel_case(comment_parts[0])
                    return '{} likelihood of "{}" {}'.format(likelihood, asset, comment).replace("\\", "")

        return comment.replace("\\", "")

    @property
    def description(self):
        if self.is_threat:
            #short_comment = self.comment
            comment = self._apd.dynamic.threats[self.uri].description
            #comment = comment[len(short_comment) + 1:]
            #comment = comment.lstrip()
            return comment.capitalize().replace("\\", "")
        elif not self.uri in self._apd.dynamic.misbehaviour_sets:
            logger.debug(f"dealing with TWA description {self.uri}")
            return f"TWA description"
        else:
            #ms = self._apd.full.misbehaviour_sets[URI_PREFIX + self.uri]
            ms = self._apd.dynamic.misbehaviour_sets[self.uri]
            ms_description = self._apd.dynamic.misbehaviours[ms.misbehaviour].description
            return ms_description.replace("\\", "")

    @property 
    def max_distance_from_target(self):
        try:
            # Probably all nodes should have a distance or should have been deleted
            # Some seem to be unreachable from the target so the next line gives an error
            d = max(self.max_distance_from_target_by_target.values())
        except:
            d = -1
        return d

    @property 
    def min_distance_from_root(self):
        return min(self.min_distance_from_root_by_cause.values())

    @property 
    def max_distance_from_root(self):
        return max(self.max_distance_from_root_by_cause.values())


    def _get_control_strategies(self):
        if not self.is_threat:
            return None
        control_strategies = self._apd.get_threat_inactive_control_strategies(self.uri, self.nodes.is_future_risk)
        # TODO: change this to just make_symbol(csg) when removing MyControlStrategy class
        control_strategy_symbols = [self._make_symbol(csg.uriref) for csg in control_strategies]
        return LogicalExpression(self._apd, control_strategy_symbols, all_required=False)

    def _get_controls(self):
        if not self.is_threat:
            return None
        # The LogicalExpression for the controls that will mitigate a threat is:
        # OR(the control strategy expressions)

        # The LogicalExpression for a control strategy is:
        # AND(the control strategy's inactive controls)

        # So we will end up with something like:
        # OR(AND(c1, c2), AND(c3), AND(c1, c4))

        control_strategies = []
        for csg_uri in self._apd.get_threat_control_strategy_uris(self.uri, self.nodes.is_future_risk):
            csets = self._apd.get_csg_inactive_control_set_uris(csg_uri)
            control_set_symbols = [self._make_symbol(cs) for cs in csets]
            control_strategies.append(LogicalExpression(self._apd, control_set_symbols, all_required=True))
        return LogicalExpression(self._apd, control_strategies, all_required=False)


    def _get_controls_orig(self):
        if not self.is_threat:
            return None
        # The LogicalExpression for the controls that will mitigate a threat is:
        # OR(the control strategy expressions)

        # The LogicalExpression for a control strategy is:
        # AND(the control strategy's inactive controls)

        # So we will end up with something like:
        # OR(AND(c1, c2), AND(c3), AND(c1, c4))

        control_strategies = []
        for csg_uri in self._apd.get_threat_control_strategy_uris(self.uri, self.nodes.is_future_risk):
            csets = self._apd.get_csg_inactive_control_set_uris(csg_uri)
            control_set_symbols = [self._make_symbol(cs) for cs in csets]
            control_strategies.append(LogicalExpression(self._apd, control_set_symbols, all_required=True))
        return LogicalExpression(self._apd, control_strategies, all_required=False)

    def _get_all_direct_cause_uris(self):
        if self.is_threat:
            return self._apd.get_threat_direct_cause_uris(self.uri)
        return self._apd.get_misbehaviour_direct_cause_uris(self.uri)

    def add_direct_cause_uris(self, uris):
        self.direct_cause_uris |= uris
        for cause_uri in uris:
            #self.nodes.get_node_by_uri(cause_uri)._add_direct_effect_uri(self.uri)
            self.nodes[cause_uri]._add_direct_effect_uri(self.uri)

    # don't call this one directly, use add_direct_cause_uris()
    def _add_direct_effect_uri(self, uri):
        self.direct_effect_uris.add(uri)

    @property
    def threatened_asset_uris(self):
        if not self.is_threat:
            return [get_misbehaviour_location_uri(self.uri)]

        asset_uris = []
        for misbehaviour_uri in self.direct_effect_uris:
            asset_uris.append(get_misbehaviour_location_uri(misbehaviour_uri))
        return asset_uris

    @property
    def involved_asset_uris(self):
        if self.is_threat:
            return get_threat_involved_asset_uris(self.uri)

        return []

    def _make_symbol(self, uri):
        #logger.debug(f"MAKE SYMBOL: {type(uri)} {uri}")
        if isinstance(uri, ControlSet):
            return symbol(uri.uri.split("#")[1])
        return symbol(uri.split('#')[1])

    def backtrace(self, current_path=None, compute_logic=True):
        if current_path is None:
            current_path = set()
        #logging.debug(" " * len(current_path) + " BACKTRACE for: " + str(self.uri).split('#')[1] + " (nodeID:" + str(self.id) + ")  current path length: " + str(len(current_path)))
        current_path = set(current_path)  # Make a copy of the set then add self
        current_path.add(self.uri)

        self.visits += 1

        # check the cached results
        if self.cannot_be_caused:
            # If this node is unreachable regardless of path taken to it
            # TODO: this can just be done with zero-length loopback_node_uris result in no_cause_results
            self.cache_hit_visits += 1
            #logging.debug(" " * len(current_path) + "Cannot be caused")
            raise TreeTraversalError()

        for result in self.no_cause_results:
            # If all of the loopback nodes in this node's causation tree are on the current path
            if len(current_path.intersection(result['loopback_node_uris'])) == len(result['loopback_node_uris']):
                self.cache_hit_visits += 1
                #logging.debug(" " * len(current_path) + "Cache hit, no cause")
                raise TreeTraversalError(result['loopback_node_uris'])

        valid_caches = []
        for result in self.cause_results:
            # If we have previously found any way for this node to be caused that does not intersect with the current path to the node then we know the cached result will be okay, so could use it.
            # This would mean that we are not looking again when we might be and therefore can miss some other good path.
            # If on a previous occasion we rejected a route because it intersected with the path then there will be some loopback_nodes. If any of the loopback_nodes are not on the current_path then there may be another route to be found.

            if len(current_path.intersection(result['all_cause_uris'])) == 0:
                # then the cached cause will still work
                valid_caches.append(result)

        if len(valid_caches):
            use_cache = True
            for result in valid_caches:
                if len(current_path.intersection(result['loopback_node_uris'])) == len(result['loopback_node_uris']):
                    # then the current path has all the loopback_nodes of the cached result so would behave the same
                    pass
                else:
                    # then in this case there is more to explore
                    logging.debug("  " * len(current_path) + "  Cache hit: node can be caused, but more to explore")
                    use_cache = False
                    break

            if use_cache:
                self.cache_hit_visits += 1
                #logging.debug("  " * len(current_path) + "  Cache hit, node can be caused, cache can be used")
                return result

        # store data from this visit to the node
        parent_min_distances_from_root = []
        parent_max_distances_from_root = []
        parent_root_causes = []
        parent_attack_mitigations_cs = []
        parent_threat_mitigations_cs = []
        parent_attack_mitigations_csg = []
        parent_threat_mitigations_csg = []
        parent_attack_trees = []
        parent_threat_trees = []
        valid_parent_uris = set()
        loopback_node_uris = set()  # nodes that cause a failure because they are on the current path
        all_cause_uris = set()

        try:
            if len(self.all_direct_cause_uris) == 0:
                # This will be top of tree misbehaviours (normal-op, external cause). Not root causes as they have parents in normal-ops.
                # TODO: can this just move to the end of the function?
                #logging.debug(" " * len(current_path) + " No direct causes")
                min_distance_from_root = -1
                max_distance_from_root = -1
                root_cause = LogicalExpression(self._apd, [self._make_symbol(self.uri)])

                if self.is_threat:
                    print("**** ERROR: There should not be a threat with no parents!: " + self.uri.split('#')[1])
                    raise Exception()  # TODO: put error in exception and choose a better Exception class

                attack_mitigated_by_cs = None
                threat_mitigated_by_cs = None
                attack_mitigated_by_csg = None
                threat_mitigated_by_csg = None
                attack_tree = None
                threat_tree = None

            elif self.is_threat:
                if len(set(self.all_direct_cause_uris) & current_path) > 0:
                    # For a threat we require all parents.
                    # If even one is on the current path then the threat is triggered by its own consequence which is useless.
                    # print("** threat dependent on its own consequence: " + self.uri.split('#')[1])
                    #logging.debug(" " * len(current_path) + " threat is directly dependent on its own consequence:" + self.uri)
                    raise TreeTraversalError(set(self.all_direct_cause_uris) & current_path)

                sorted_causes = sorted(list(self.all_direct_cause_uris))
                #logging.debug(" " * len(current_path) + " " + str(len(sorted_causes)) + " direct causes of threat")
                #logging.debug(" " * len(current_path) + "   └─>[" + ", ".join(sorted_causes) + "]")
                for parent_uri in sorted_causes:
                    parent = self.nodes.get_or_create_node(parent_uri)
                    try:
                        p_result = parent.backtrace(current_path, compute_logic)
                    except TreeTraversalError as error:
                        # print("** threat with error: " + self.uri.split('#')[1])
                        loopback_node_uris |= error.loopback_node_uris
                        # loopback_node_uris.add(parent_uri)
                        # TODO: At this point, if another parent has previously successfully been backtraced, then that parent will be left hanging with no direct_effects set as this node is found to be invalid. We need to remove these hanging nodes here or later.
                        raise TreeTraversalError(loopback_node_uris)
                    else:
                        valid_parent_uris.add(parent_uri)
                        loopback_node_uris |= p_result['loopback_node_uris']
                        all_cause_uris |= p_result['all_cause_uris']
                        if (self.is_normal_op == parent.is_normal_op) and not parent.is_external_cause:  # Fully in one region or the other
                            parent_min_distances_from_root.append(p_result['min_distance'])
                            parent_max_distances_from_root.append(p_result['max_distance'])
                            parent_root_causes.append(p_result['root_cause'])

                        if compute_logic:
                            p_attack_mitigation_cs, p_threat_mitigation_cs, p_attack_mitigation_csg, p_threat_mitigation_csg, p_attack_tree, p_threat_tree = p_result['data']
                            parent_threat_mitigations_cs.append(p_threat_mitigation_cs)  # Entire path
                            parent_threat_mitigations_csg.append(p_threat_mitigation_csg)  # Entire path
                            parent_threat_trees.append(p_threat_tree)
                            if not parent.is_normal_op and not parent.is_external_cause:
                                parent_attack_mitigations_cs.append(p_attack_mitigation_cs)  # Just attack path
                                parent_attack_mitigations_csg.append(p_attack_mitigation_csg)  # Just attack path
                                parent_attack_trees.append(p_attack_tree)

                if len(parent_root_causes) == 0:
                    # Then this is a root cause threat
                    parent_min_distances_from_root = [-1]
                    parent_max_distances_from_root = [-1]
                    parent_root_causes.append(LogicalExpression(self._apd, [self._make_symbol(self.uri)]))

                # The root cause of a threat is all (AND) of the root causes of its parents
                root_cause = LogicalExpression(self._apd, parent_root_causes, all_required=True)

                # The distance from a root cause therefore is the maximum of the parent distances + 1
                min_distance_from_root = max(parent_min_distances_from_root) + 1
                max_distance_from_root = max(parent_max_distances_from_root) + 1

                #logging.debug(" " * len(current_path) + "Finished looking at threat causes " +
                #        "(nodeID:" + str(self.id) + ") min distance: " + str(min_distance_from_root))

                if compute_logic:
                    # The attack/threat tree is
                    # AND(
                    #   the threat itself
                    #   all the parent threat tree
                    # )
                    if not self.is_normal_op:
                        # If this threat (self) is on the attack path then it can itself be a mitigation on the attack_path
                        parent_attack_trees.append(self.uri_symbol)
                    attack_tree = LogicalExpression(self._apd, parent_attack_trees, all_required=True)

                    # All threats are on the threat path
                    parent_threat_trees.append(self.uri_symbol)
                    threat_tree = LogicalExpression(self._apd, parent_threat_trees, all_required=True)

                    # A threat can be mitigated by
                    # OR(
                    #   inactive control strategies located at itself
                    #   mitigations of any of its parents
                    # )
                    if not self.is_normal_op:
                        # If this threat (self) is on the attack path then it can itself be a mitigation on the attack_path
                        parent_attack_mitigations_cs.append(self.controls)
                        parent_attack_mitigations_csg.append(self.control_strategies)
                    # All threats are a mitigation of the complete threat path
                    parent_threat_mitigations_cs.append(self.controls)
                    parent_threat_mitigations_csg.append(self.control_strategies)

                attack_mitigated_by_cs = LogicalExpression(self._apd, parent_attack_mitigations_cs, all_required=False)
                threat_mitigated_by_cs = LogicalExpression(self._apd, parent_threat_mitigations_cs, all_required=False)
                attack_mitigated_by_csg = LogicalExpression(self._apd, parent_attack_mitigations_csg, all_required=False)
                threat_mitigated_by_csg = LogicalExpression(self._apd, parent_threat_mitigations_csg, all_required=False)

            else:
                # we are a misbehaviour with direct causes
                loopback_node_uris = set(self.all_direct_cause_uris) & current_path
                sorted_causes = sorted(list(set(self.all_direct_cause_uris) - current_path))
                #logging.debug(" " * len(current_path) + " " + str(len(sorted_causes)) + " direct causes of MS")
                #logging.debug(" " * len(current_path) + "   └─>[" + ", ".join(sorted_causes) + "]")
                #for i in sorted_causes:
                #    logging.debug(" " * len(current_path) + " " +str(i))
                for parent_uri in sorted_causes:
                    parent = self.nodes.get_or_create_node(parent_uri)
                    try:
                        p_result = parent.backtrace(current_path, compute_logic)
                    except TreeTraversalError as error:
                        loopback_node_uris |= error.loopback_node_uris
                        # loopback_node_uris.add(parent_uri)
                    else:
                        valid_parent_uris.add(parent_uri)
                        loopback_node_uris |= p_result['loopback_node_uris']
                        all_cause_uris |= p_result['all_cause_uris']
                        parent_min_distances_from_root.append(p_result['min_distance'])
                        parent_max_distances_from_root.append(p_result['max_distance'])
                        parent_root_causes.append(p_result['root_cause'])

                        if compute_logic:
                            p_attack_mitigation_cs, p_threat_mitigation_cs, p_attack_mitigation_csg, p_threat_mitigation_csg, p_attack_tree, p_threat_tree = p_result['data']
                            parent_threat_mitigations_cs.append(p_threat_mitigation_cs)  # Entire path
                            parent_threat_mitigations_csg.append(p_threat_mitigation_csg)  # Entire path
                            parent_threat_trees.append(p_threat_tree)
                            if not parent.is_normal_op:
                                parent_attack_mitigations_cs.append(p_attack_mitigation_cs)  # Just attack path
                                parent_attack_mitigations_csg.append(p_attack_mitigation_csg)  # Just attack path
                                parent_attack_trees.append(p_attack_tree)

                if len(valid_parent_uris) == 0:
                    # Then all parents have thrown exceptions or were on the current path
                    #logging.debug(" " * len(current_path) + " misbehaviour with all parents invalid: " + self.uri + " (nodeID:" + str(self.id) + ")")
                    raise TreeTraversalError(loopback_node_uris)

                # The root_cause of a misbehaviour is any (OR) of the root causes of its parents
                root_cause = LogicalExpression(self._apd, parent_root_causes, all_required=False)

                # The distance from a root cause is therefore the minimum of the parent distances
                min_distance_from_root = min(parent_min_distances_from_root) + 1
                max_distance_from_root = min(parent_max_distances_from_root) + 1

                #logging.debug(" " * len(current_path) + "Finished looking at MS causes " +
                #        "(nodeID:" + str(self.id) + ") min distance: " + str(min_distance_from_root))

                if compute_logic:
                    # The attack/threat path is
                    # OR(
                    #   all the parent threat paths
                    # )
                    attack_tree = LogicalExpression(self._apd, parent_attack_trees, all_required=False)
                    threat_tree = LogicalExpression(self._apd, parent_threat_trees, all_required=False)

                # Misbehaviours can be mitigated by
                # AND(
                #   mitigations of their parents
                # )
                attack_mitigated_by_cs = LogicalExpression(self._apd, parent_attack_mitigations_cs, all_required=True)
                threat_mitigated_by_cs = LogicalExpression(self._apd, parent_threat_mitigations_cs, all_required=True)
                attack_mitigated_by_csg = LogicalExpression(self._apd, parent_attack_mitigations_csg, all_required=True)
                threat_mitigated_by_csg = LogicalExpression(self._apd, parent_threat_mitigations_csg, all_required=True)

        except TreeTraversalError as error:
            #logging.debug(" " * len(current_path) + "Error " + self.uri + " (nodeID:" + str(self.id) + ")")
            loopback_node_uris = error.loopback_node_uris
            loopback_node_uris_on_path = (current_path & loopback_node_uris)
            loopback_node_uris_on_path.discard(self.uri)  # just look at the path to self, not self itself
            if len(loopback_node_uris_on_path) == 0:
                self.cannot_be_caused = True
                result = {}
            else:
                result = {
                    'loopback_node_uris': loopback_node_uris_on_path
                }
            self.no_cause_results.append(result)
            self.no_cause_visits += 1
            raise TreeTraversalError(loopback_node_uris_on_path)

        else:

            # If we've got this far then the node is on a workable path

            self.not_a_cause = False  # Set to "True" on initialisation but not elsewhere, so this means that the node is on *at least one* workable path

            # Keep track of which direct cause Nodes enabled this Node (also adds this node as an effect of the cause)
            self.add_direct_cause_uris(valid_parent_uris)

            # Add the direct causes to the accumulated direct causes' causes
            all_cause_uris |= valid_parent_uris

            loopback_node_uris.discard(self.uri)

            # At this point we have a distance_from_root, root_cause and mitigation for the current_path.
            # We return those to be used in the child that called this method on this node, but before that
            # we need to merge the results with any others that have previously been found from other paths to this node.
            # Interestingly, when combining causes over different paths, the logic is reversed.

            self.root_cause = LogicalExpression(self._apd, [self.root_cause, root_cause], all_required=False)

            # Save the max and min distances from this root cause
            # The max is useful to spread things out for display
            # The min is useful to find shortest paths
            self.max_distance_from_root_by_cause[root_cause] = max(self.max_distance_from_root_by_cause.get(root_cause, -1), max_distance_from_root)
            self.min_distance_from_root_by_cause[root_cause] = min(self.max_distance_from_root_by_cause.get(root_cause, INFINITY), min_distance_from_root)

            # Although tempting to calculate the distance from target here, we can't because we don't know if the current tree is going to be successful all the way back to the target.

            if compute_logic:
                self.attack_tree_mitigation_cs = LogicalExpression(self._apd, [self.attack_tree_mitigation_cs, attack_mitigated_by_cs], all_required=True)
                self.threat_tree_mitigation_cs = LogicalExpression(self._apd, [self.threat_tree_mitigation_cs, threat_mitigated_by_cs], all_required=True)
                self.attack_tree_mitigation_csg = LogicalExpression(self._apd, [self.attack_tree_mitigation_csg, attack_mitigated_by_csg], all_required=True)
                self.threat_tree_mitigation_csg = LogicalExpression(self._apd, [self.threat_tree_mitigation_csg, threat_mitigated_by_csg], all_required=True)
                self.attack_tree = LogicalExpression(self._apd, [self.attack_tree, attack_tree], all_required=False)
                self.threat_tree = LogicalExpression(self._apd, [self.threat_tree, threat_tree], all_required=False)

            result = {
                'loopback_node_uris': loopback_node_uris,
                'all_cause_uris': all_cause_uris,
                'max_distance': max_distance_from_root,
                'min_distance': min_distance_from_root,
                'root_cause': root_cause
            }

            if compute_logic:
                result["data"] = (attack_mitigated_by_cs, threat_mitigated_by_cs, attack_mitigated_by_csg, threat_mitigated_by_csg, attack_tree, threat_tree)

            self.cause_results.append(result)
            self.cause_visits += 1
            return result

class TreeTraversalError(Exception):
    """Some error when recursing over tree"""
    def __init__(self, loopback_node_uris: set = None) -> None:
        if loopback_node_uris is None: loopback_node_uris = set()
        self.loopback_node_uris = loopback_node_uris

class LogicalExpression():
    """Represents a Boolean expression using URI fragments as the symbols."""
    def __init__(self, apd, cause_list, all_required=True):
        """Arguments:

        cause_list: list
                can be a mixture of None, LogicalExpression and symbol
        all_required: Boolean
                whether all the parts of the expression are required (resulting in an AND) or not (giving an OR)
        """

        self._apd = apd
        self.cl = cause_list
        #logger.debug(f"LLE: {cause_list}")
        #for cc in cause_list:
        #    if isinstance(cc, LogicalExpression):
        #        logger.debug(f"\t\tCC {cc.pretty_print()}")
        #    else:
        #        logger.debug(f"\t\tType {type(cc)}")

        all_causes = []
        for cause in cause_list:
            if isinstance(cause, LogicalExpression):
                all_causes.append(cause.cause)
            else:
                all_causes.append(cause)

        all_causes = [cc for cc in all_causes if cc is not None]

        if len(all_causes) == 0:
            #logger.debug(f"NONE CAUSE for cause_list of {len(cause_list)}")
            self.cause = None
        elif len(all_causes) == 1:
            #logger.debug(f"LE ONE: {all_causes}")
            self.cause = all_causes[0]
        else:
            if all_required:
                self.cause = AND(*all_causes).simplify()
                #logger.debug(f"LE ALL: {all_causes}")
            else:
                self.cause = OR(*all_causes).simplify()

    def apply_dnf(self, max_complexity=100):
        """ apply DNF """

        if self.cause is None:
            return
        cause_complexity = str(self.cause.args).count("Symbol")
        if cause_complexity <= max_complexity:
            self.cause = algebra.dnf(self.cause.simplify())

    def __str__(self):
        return self.pretty_print()
        #return self.pp()

    def __eq__(self, other):
        return self.cause == other.cause

    def __hash__(self) -> int:
        return hash(self.cause)

    def is_empty(self):
        if isinstance(self, boolean.Symbol):
            return False
        elif isinstance(self, AND):
            return False
        elif isinstance(self. OR):
            return False
        else:
            return True

    @property
    def uris(self):
        #return set([URIRef(SYSTEM + "#" + str(symbol)) for symbol in self.cause.get_symbols()])
        #return set(["system#" + str(symbol) for symbol in self.cause.get_symbols()])
        symbol_set = set()
        #logger.debug(f"CAUSE TYPE: {self.cause} {type(self.cause)}")
        #if not self.cause == None:
        if not self.cause is None:
            for symbol in self.cause.get_symbols():
                symbol_set.add(symbol)
        return symbol_set

    def pretty_print_d(self, max_complexity=100):
        if self.cause is None:
            return "-None-"
        cause_complexity = str(self.cause.args).count("Symbol")
        if cause_complexity <= max_complexity:
            cause = algebra.dnf(self.cause.simplify())
            symb = re.compile(r'Symbol\(\'.*?\'\)')
            cause = symb.sub(MyControlStrategy.get_by_dummy_uriref_d, cause.pretty())
        else:
            cause = "Complexity: " + str(cause_complexity)
        return cause


    def pretty_print_e(self, max_complexity=100):
        if self.cause is None:
            return "-None-"
        #logger.debug(f"CAUSE TYPE, {type(self.cause)}")
        #logger.debug(f"CAUSE, {self.cause}")
        cause_complexity = str(self.cause.args).count("Symbol")
        if cause_complexity <= max_complexity:
            cause = algebra.dnf(self.cause.simplify())
            cause = self.cause.simplify().pretty()
            cause = re.sub(r"Symbol\('|'\)", "", cause)
        else:
            cause = "Complexity: " + str(cause_complexity)
        return cause

    def pretty_print(self, max_complexity=100):
        if self.cause is None:
            return "-None-"
        cause_complexity = str(self.cause.args).count("Symbol")
        if cause_complexity <= max_complexity:
            cause = algebra.dnf(self.cause.simplify())
            symb = re.compile(r'Symbol\(\'.*?\'\)')
            cause = symb.sub(self.get_comment_from_match, cause.pretty())
        else:
            cause = "Complexity: " + str(cause_complexity)
        return cause

    def get_comment_from_match(self, frag_match):
        #logger.debug(f"FROM MATCH: {type(frag_match)}, {frag_match}")
        return self.get_comment(str(frag_match.group()[8:-2]))

    def get_ms_comment(self, uriref):
        likelihood = self._apd.likelihood_label[uriref]
        label = self._apd.dynamic.misbehaviour_sets[uriref].label
        comment_parts = label.split('-', 2)  # e.g. MS-LossOfConfidentiality-SourceCode
        asset = comment_parts[2]
        if "LossOf" in comment_parts[1] or "Not" in comment_parts[1]:
            aspect = un_camel_case(comment_parts[1][6:])
            if "LossOf" in comment_parts[1]:
                consequence = "loses"
            else:
                consequence = "is not"
            return '{} likelihood that "{}" {} {}'.format(likelihood, asset, consequence, aspect)
        comment = un_camel_case(comment_parts[1]) + ' at "' + un_camel_case(comment_parts[2]) + '"'
        return comment

    def get_csg_comment(self, dummy_csg_uri):
        # TODO: change this to not use the MyControlStrategy once we can
        if not dummy_csg_uri.startswith("system#"):
            dummy_csg_uri = "system#" + dummy_csg_uri
        my_csg = MyControlStrategy.get_by_dummy_uriref(dummy_csg_uri)
        # cs_comment = "AND(" + ", ".join([get_cs_comment(cs) for cs in my_csg.inactive_control_set_uris]) + ")"
        # comment = "{}: {}".format(my_csg.label, cs_comment)
        # comment = "{}: {}".format(my_csg.label, my_csg.description)
        # comment = "{}".format(my_csg.label)
        asset_labels = list(set(self.get_csg_asset_labels(my_csg)))  # get unique set of asset labels the CSG involves (whether proposed or not)
        asset_labels = [self.abbreviate_asset_label(label) for label in asset_labels]
        asset_labels.sort()
        comment = "{} ({})".format(my_csg.label, ", ".join(asset_labels))
        return comment

    def get_csg_asset_uris(self, csg_uri):
        cs_uris = self._apd.get_csg_control_set_uris(csg_uri)
        asset_uris = []
        for cs_uri in cs_uris:
            #asset_uris.append(cs_uri.asset_uri[60:])
            asset_uris.append(cs_uri.located_at)
        return asset_uris

    def get_csg_asset_labels(self, csg_uri):
        labels = []
        for asset in self.get_csg_asset_uris(csg_uri):
            label = self._apd.assets[asset].label
            labels.append(label)
        return labels


    def abbreviate_asset_label(self, label):
        if label.startswith("[ClientServiceChannel:"):
            # Example input:
            # [ClientServiceChannel:(Philip's PC)-(Philip's Web Browser)-(Web Server)-Website-[NetworkPath:Internet-[NetworkPath:(Shop DMZ)]]]
            bits = label.split("-")
            return "[ClientServiceChannel:" + bits[1] + "-" + bits[3]
        return label

    def get_comment(self, uriref):
        #logger.debug(f"GET COMMENT: {uriref}, {type(uriref)}")
        if "system#"+uriref in self._apd.dynamic.misbehaviour_sets:
            return self.get_ms_comment("system#" + uriref)

        if "system#"+uriref in self._apd.cs_dict:
            return self.get_cs_comment("system#"+uriref)

        if "system#"+uriref in self._apd.dynamic.threats:
            return self._apd.dynamic.threats["system#"+uriref].label

        if DUMMY_CSG in uriref:
            return self.get_csg_comment(uriref)

        logger.warning(f"CANNOT find comment for {uriref}")
        return uriref

        if comment is not None:
            if SHORT_THREATS:
                quote_counter = 0
                char_index = 0
                while (comment[char_index] != ":" or quote_counter % 2 != 0):
                    if comment[char_index] == '"':
                        quote_counter += 1
                    char_index += 1
                comment = comment[0:char_index]
            return comment

        if str(uriref).startswith("http://"):
            label = graph.label(subject=uriref, default=None)

            if label is not None:
                return label

            if str(uriref).startswith(CORE):
                label = "core" + str(uriref)[len(CORE):]
            elif str(uriref).startswith(DOMAIN):
                label = "domain" + str(uriref)[len(DOMAIN):]

        else:
            label = str(uriref)

        return label

    def get_cs_comment(self, cs_uri):
        control_label = self._apd.cs_dict[cs_uri].label
        asset_uri = self._apd.cs_dict[cs_uri].asset_uri[60:]

        if asset_uri in self._apd.assets:
            asset_label = self._apd.assets[asset_uri].label
        else:
            logger.warning(f"CS asset not found: cs_uri {cs_uri}, asset uri {asset_uri}")
            asset_label = f"-CS_{asset_uri}-"

        if asset_label[0] != "[":
            asset_label = '"' + asset_label + '"'

        return control_label + " at " + asset_label

    def get_list_from_or(self):
        """ take a logical expression and return a list of ANDS (assuming input
            is in DNF form)
        """
        ret_val = []
        if self.cause == None:
            logger.debug(f"Logical expression cause is none, cannot find mitigation CSG")
        elif isinstance(self.cause, boolean.Symbol):
            ret_val.append(self.cause)
        elif isinstance(self.cause, boolean.OR):
            for option in self.cause.args:
                ret_val.append(option)
                logger.debug(f"convert CSG option, adding {option}")
        elif isinstance(self.cause, boolean.AND):
            ret_val = [self.cause]
        else:
            logger.error(f"convert_csg_options: Logical Expression operator not supported")

        return ret_val

    def get_list_from_and(self):
        """ take a logical expression and return a list of symbols
        """
        ret_val = []
        if isinstance(self.cause, boolean.AND):
            for option in self.cause.args:
                ret_val.append(option)
                logger.debug(f"convert CSG option, adding {option}")
        elif isinstance(self.cause, boolean.Symbol):
            ret_val = [self.cause]
        else:
            logger.error(f"convert_csg_options: Logical Expression operator not supported {self.cause.operator} {self.cause}")

        return ret_val


    def convert_csg_options(self):
        """ convert from CSG_logical_expression to list of CSG_options"""
        csg_options = []
        if self.cause == None:
            logger.debug(f"Logical expression cause is none, cannot find mitigation CSG")
            return []
        elif isinstance(self.cause, boolean.Symbol):
            csg_options.append(self.cause)
        elif isinstance(self.cause, boolean.OR):
            for option in self.cause.args:
                csg_options.append(option)
                logger.debug(f"convert CSG option, adding {option}")
        elif isinstance(self.cause, boolean.AND):
            tt = []
            for option in self.cause.args:
                tt.append(option)
                logger.debug(f"convert CSG option, adding {option}")
            csg_options.append(tt)
        else:
            logger.error(f"convert_csg_options: Logical Expression operator not supported {self.cause.operator} {self.cause}")

        return csg_options

    def convert_csg_symbols(self):
        """ convert from symbol or AND() to CSG_list """
        csg_uris = []
        if isinstance(self, Symbol):
            #csg_uris.append("system#" + option.obj)
            csg_uris.append(self.obj)
        elif isinstance(self.cause, AND):
            for symbol in option.cause.args:
                #csg_uris.append("system#" + option.obj)
                csg_uris.append(symbol.obj)
        else:
            logger.error(f"Logical Expression operator not supported {self.cause.operator}")

        return csg_uris


def un_camel_case(text):
    if text == "": return "****"
    text = text.replace("TW", "Trustworthiness")
    if not text[0] == "[":
        text = re.sub('([a-z])([A-Z])', r'\1 \2', text)
        text = text.replace("Auth N", "AuthN")
        text = re.sub('(AuthN)([A-Z])', r'\1 \2', text)  # re-join "AuthN" into one word
        text = re.sub('([A-Z]{2,})([A-Z][a-z])', r'\1 \2', text)  # split out e.g. "PIN" or "ID" as a separate word
        text = text.replace('BIO S', 'BIOS ')  # one label is "BIOSatHost"
    return text

