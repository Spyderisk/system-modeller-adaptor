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
##      Created Date :          2021-01-19
##      Created for Project :   ProTego
##
##///////////////////////////////////////////////////////////////////////

from collections import defaultdict
import textwrap
from graphviz import Digraph

from fastapi.logger import logger

INFINITY = 99999999

# General plot options:
CONSTRAIN_BACK_LINKS = True  # try to force all links to go down the page
ALIGN_ROOT_CAUSES = False  # align the root causes
ALIGN_TARGET_EFFECTS = True  # align the target effects
TOP_TO_BOTTOM = True  # choose whether to plot top to bottom or left to right

# Node plot options:
TEXT_WIDTH = 40  # word-wrap limit in nodes
SHOW_DISTANCE_FROM_ROOT = False  # show the distance from the nearest root cause on each node
SHOW_THREAT_DESCRIPTION = False  # show full threat descriptions
SHOW_EFFECT_DESCRIPTION = False  # show full effect descriptions
SHOW_LIKELIHOOD = False  # display each node's likelihood
SHOW_ROOT_CAUSE = False  # show the root cause of each node
SHOW_ATTACK_MITIGATION_CS = False  # show the attack tree control set mitigation Boolean expression on each node
SHOW_THREAT_MITIGATION_CS = False  # show the threat tree control set mitigation Boolean expression on each node
SHOW_ATTACK_MITIGATION_CSG = False  # show the attack tree control strategy mitigation Boolean expression on each node
SHOW_THREAT_MITIGATION_CSG = False  # show the threat tree control strategy mitigation Boolean expression on each node
SHOW_ATTACK_TREE = False  # show the attack tree on each node
SHOW_THREAT_TREE = False  # show the threat tree on each node
SHOW_CAUSE_URIS = False  # show the URIs of a node's direct causes
SHOW_URI = False  # show the URI of a node
SHOW_CACHE_DEBUG = False  # show the number of visits and results of different types on each node
SHOW_RANK = False  # show the "rank" of each node (useful for debugging)

def plot_rec_csg(graph_fname, nodes, links, show=False):
    logger.info("Creating dot graph for recommendations tree")
    dot = Digraph(name="Topology", node_attr={"shape": "box"})

    # plot nodes:
    for node in nodes:
        tokens = node.split(", ")
        text = ", AND ".join([x.split("_")[-1] for x in tokens])
        dot.node(node, text)

    # plot relations
    for link in links:
        dot.edge(link[0], link[1])

    dot.format = 'svg'
    dot.attr(label=f"{graph_fname}_label")

    # display grap on sceen
    if show:
        dot.render(graph_fname, view=True)

    output = dot.pipe()

def plot_graph(filename, nodes_to_plot, links_to_plot, rank_by_uri, highlighted_nodes, output_format:str = ''):
    """Plot a graph of the attack tree.

    filename: filename to write to
    nodes_to_plot: set of TreeNode objects to include in the plot
    links_to_plot: set of (node, predicate, node) tuples to plot (only those where both ends are in the nodes_to_plot set are used)
    rank_by_uri: dictionary describing the numeric rank of each node using the node.uri as the key
    highlighted_nodes: set of nodes which should be highlighted
    """

    # the neato engine does a pretty good job but ignores the ranks
    # gv = Digraph(engine="neato")
    # the dot engine uses the rank info provided
    gv = Digraph(engine="dot")
    gv.attr("node", shape="box")
    gv.attr(overlap="scale")  # "false" is often good but need to use "scale" in Windows because Windows binary does not inlcude necessary lib
    gv.attr(splines="true")  # "true" means arrows avoid nodes (but also means it is not the same style as SSM)
    gv.attr(newrank="true")
    gv.attr(nodesep="1")
    gv.attr(ranksep="1")
    gv.attr(pagedir="BL")
    if TOP_TO_BOTTOM:
        gv.attr(rankdir="TB")
    else:
        gv.attr(rankdir="LR")

    format_ext = output_format.lower()
    if format_ext == 'svg':
        gv.format = 'svg'
    elif format_ext == 'png':
        gv.format = 'png'

    gv.attr(label=f"<<B>Shortest attack path graph for model: {filename}</B>>")
    gv.attr(labelloc = 't')
    gv.attr(fontsize = '40')
    #gv.attr(fontname = 'times-bold')
    #gv.attr(bgcolor = 'lightgray')
    gv.attr(bgcolor = 'gray98')

    nodes_to_plot = sorted(nodes_to_plot, key=lambda n: n.uri)

    if ALIGN_ROOT_CAUSES or ALIGN_TARGET_EFFECTS:
        nodes_by_rank = defaultdict(list)
        for node in nodes_to_plot:
            nodes_by_rank[rank_by_uri.get(node.uri, INFINITY)].append(node)

        ranks = list(nodes_by_rank.keys())
        ranks.sort()

        for rank in ranks:
            with gv.subgraph() as sub:
                sub.attr(rank="same")
                for node in nodes_by_rank[rank]:
                    plot_node(sub, node, node in highlighted_nodes, rank)
    else:
        for node in nodes_to_plot:
            plot_node(gv, node, node in highlighted_nodes)

    for link in links_to_plot:
        start_node, predicate, end_node = link
        if start_node not in nodes_to_plot or end_node not in nodes_to_plot:
            continue
        is_from_normal_op = start_node.is_normal_op
        if ALIGN_ROOT_CAUSES or ALIGN_TARGET_EFFECTS:
            is_back_link = rank_by_uri[start_node.uri] >= rank_by_uri[end_node.uri]
            if ALIGN_TARGET_EFFECTS: is_back_link = not is_back_link  # reverse the logic in this case
            is_back_link = is_back_link and not is_from_normal_op  # not quite correct as back links within the normal ops area will not be flagged, but good enough
        else:
            is_back_link = False
        is_highlighted = start_node in highlighted_nodes and end_node in highlighted_nodes
        plot_link(gv, link, is_back_link, is_from_normal_op, is_highlighted)

    output = gv.pipe()
    logger.debug(f"Graph plot output: size {len(output)}, type: {type(output)} {output[:100]}...")
    return output

def plot_node(gv, node, is_highlighted=True, rank=None):

    uriref = node.uri

    attr = {"style": "filled", "color": "#333333", "margin": "0.3,0.3",
            "href": f"http://localhost/system-modeller/{uriref[7:]}"}

    if node.is_threat:
        if node.is_normal_op:
            node_type = "Normal Operation"
            attr["fillcolor"] = "#ffffff"
        else:
            if node.is_root_cause:
                node_type = "Root Cause Threat"
                attr["fillcolor"] = "#ff6565"  # ff0000 40% lighter
                attr["penwidth"] = "6"
            else:
                attr["fillcolor"] = "#ff9999"  # ff0000 60% lighter
                if node.is_secondary_threat:
                    node_type = "Secondary Threat"
                else:
                    node_type = "Primary Threat"
            if not is_highlighted:
                attr["fillcolor"] = "#ffe5e5"  # ff0000 90% lighter
    else:
        if node.is_external_cause:
            node_type = "External Cause"
            attr["fillcolor"] = "#ffd700"
            attr["penwidth"] = "6"
        elif node.is_normal_op:
            node_type = "Normal Effect"
            attr["fillcolor"] = "#ffffff"
        else:
            node_type = "Consequence"
            if node.is_target_ms:
                attr["fillcolor"] = "#ffd700"
            else:
                attr["fillcolor"] = "#ffef99"  # 60% lighter
        if not is_highlighted:
            attr["fillcolor"] = "#fffbe5"  # 90% lighter

    #text = ["<B>{}</B>".format(node_type), textwrap.fill(node.comment, TEXT_WIDTH)]
    #node_header = "<a xlink:href=\"http://www.it-innovation.soton.ac.uk/\" target=\"_top\"><B>{}</B></a>".format(node_type)
    node_header = "<B>{}</B>".format(node_type)
    text = [node_header, textwrap.fill(node.comment, TEXT_WIDTH)]
    attr['tooltip'] = uriref[7:]

    if (node.is_threat and SHOW_THREAT_DESCRIPTION) or SHOW_EFFECT_DESCRIPTION:
        text.append(textwrap.fill(node.description, TEXT_WIDTH))

    if SHOW_RANK and rank != None:
        text.append("Rank: {}".format(rank))

    if SHOW_DISTANCE_FROM_ROOT and node.distance_from_root != 0:
        text.append("Distance from root: {}".format(node.distance_from_root))

    if SHOW_LIKELIHOOD:
        text.append("Likelihood: {}".format(node.likelihood))

    if SHOW_ROOT_CAUSE and not node.is_root_cause and not node.is_external_cause:
        text.append("Root cause:\n" + str(node.root_cause).replace("\n", "\l") + "\l")

    # Don't show attack tree on normal-ops
    if SHOW_ATTACK_TREE and not node.is_normal_op:
        text.append("Attack tree:\n" + str(node.attack_tree).replace("\n", "\l") + "\l")

    # Don't show attack path mitigation on normal-ops
    if SHOW_ATTACK_MITIGATION_CS and not node.is_normal_op:
        text.append("Controls to block attack:\n" + str(node.attack_tree_mitigation_cs).replace("\n", "\l") + "\l")

    # Don't show attack path mitigation on normal-ops
    if SHOW_ATTACK_MITIGATION_CSG and not node.is_normal_op:
        text.append("Control strategies to block attack:\n" + str(node.attack_tree_mitigation_csg).replace("\n", "\l") + "\l")

    # Don't show threat tree if it's the same as the attack tree (and we're showing that)
    if SHOW_THREAT_TREE and not (SHOW_ATTACK_TREE and str(node.attack_tree) == str(node.threat_tree)):
        text.append("Threat tree:\n" + str(node.threat_tree).replace("\n", "\l") + "\l")

    # Don't show threat path mitigation if it's the same as the attack path mitigation (and we're showing that)
    if SHOW_THREAT_MITIGATION_CS and not (SHOW_ATTACK_MITIGATION_CS and str(node.attack_tree_mitigation_cs) == str(node.threat_tree_mitigation_cs)):
        text.append("Controls to block threat:\n" + str(node.threat_tree_mitigation_cs).replace("\n", "\l") + "\l")

    # Don't show threat path mitigation if it's the same as the attack path mitigation (and we're showing that)
    if SHOW_THREAT_MITIGATION_CSG and not (SHOW_ATTACK_MITIGATION_CSG and str(node.attack_tree_mitigation_csg) == str(node.threat_tree_mitigation_csg)):
        text.append("Control strategies to block threat:\n" + str(node.threat_tree_mitigation_csg).replace("\n", "\l") + "\l")

    if SHOW_CAUSE_URIS:
        # Put parentheses round normal-ops
        text.append("Direct causes:")
        # sort the parents so that we get a consistent comparable plot
        for direct_cause_uri in sorted(node.direct_cause_uris):
            # TODO: remove use of global threat_tree here
            if not threat_tree[direct_cause_uri].is_normal_op:
                text.append(get_comment(direct_cause_uri.split('#')[1]))
            else:
                text.append("(" + get_comment(direct_cause_uri.split('#')[1]) + ")")

    if SHOW_CACHE_DEBUG:
        text.append("Cache hits / Visits: {} / {}".format(node.cache_hit_visits, node.visits))
        text.append("Cause / No cause: {} / {}".format(node.cause_visits, node.no_cause_visits))

    if ALIGN_ROOT_CAUSES or ALIGN_TARGET_EFFECTS:
        attr["rank"] = str(rank)

    if SHOW_URI:
        text.append("<I>" + str(uriref).split('#')[1] + "</I>")

    text = "<BR/><BR/>".join(text)
    text = text.replace("\n", "<BR/>")
    #text = text.replace("\l", '<BR ALIGN="LEFT"/>')
    text = text.replace("\l", '<BR/>')
    text = text.replace("->", "&gt;")

    gv.node(uriref[7:], "<" + text + ">", **attr)

def plot_link(gv, link, is_back_link, is_from_normal_op, is_highlighted):
    start_uri = link[0].uri
    label = link[1]
    end_uri = link[2].uri

    attr = {"fontcolor": "black", "color": "black", "style": "solid", "penwidth": "3"}
    if TOP_TO_BOTTOM:
        attr["tailport"] = "s"
        attr["headport"] = "n"
    else:
        attr["tailport"] = "e"
        attr["headport"] = "w"

    if is_from_normal_op:
        attr["style"] = "dotted"
    if is_back_link or not is_highlighted:
        attr["color"] = "gray"

    # If the "constraint" attr is True then dot will try to place the end further down the page than the start.
    # If it is false then dot does not worry about the relative placement
    constraint = CONSTRAIN_BACK_LINKS or not is_back_link

    # if end_uri in threatened_assets:
    #     constraint = False
    #     attr["tailport"]="center"
    #     attr["headport"]="center"
    #     if predicate == PATH_THREATENS:
    #         attr["color"] = "pink"
    #     else:
    #         attr["color"] = "lightblue"
    #     attr["style"] = "solid"
    #     attr["fontcolor"] = "#83A3AD"

    attr["constraint"] = str(constraint)

    gv.edge(start_uri[7:], end_uri[7:], label, **attr)

