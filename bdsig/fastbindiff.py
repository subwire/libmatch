
import logging
import math
import types
from collections import deque

import networkx

from angr.errors import SimEngineError, SimMemoryError

# todo include an explanation of the algorithm
# todo include a method that detects any change other than constants
# todo use function names / string references where available

l = logging.getLogger("angr.analyses.bindiff")

# basic block changes
DIFF_TYPE = "type"
DIFF_VALUE = "value"


# exception for trying find basic block changes
class UnmatchedStatementsException(Exception):
    pass


# statement difference classes
class Difference(object):
    def __init__(self, diff_type, value_a, value_b):
        self.type = diff_type
        self.value_a = value_a
        self.value_b = value_b


class ConstantChange(object):
    def __init__(self, offset, value_a, value_b):
        self.offset = offset
        self.value_a = value_a
        self.value_b = value_b


class LibMatch(object):
    def __init__(self, prog_addr, lib_addr, lib_func_name, lib_name):
        self.prog_addr = prog_addr
        self.lib_addr = lib_addr
        self.lib_func_name = lib_func_name
        self.lib_name = lib_name

    def __str__(self):
        return "Match: %#x is %s (%#x) from %s" % (self.prog_addr,
                                                   self.lib_func_name,
                                                   self.lib_addr,
                                                   self.lib_name)

    def __repr__(self):
        return "<LibMatch in prog at %#x to %s (%#x) in %s>" % (self.prog_addr,
                                                                self.lib_func_name,
                                                                self.lib_addr,
                                                                self.lib_name)


# helper methods
def _euclidean_dist(vector_a, vector_b):
    """
    :param vector_a:    A list of numbers.
    :param vector_b:    A list of numbers.
    :returns:           The euclidean distance between the two vectors.
    """
    dist = 0
    for (x, y) in zip(vector_a, vector_b):
        dist += (x-y)*(x-y)
    return math.sqrt(dist)


def _get_closest_matches(input_attributes, target_attributes):
    """
    :param input_attributes:    First dictionary of objects to attribute tuples.
    :param target_attributes:   Second dictionary of blocks to attribute tuples.
    :returns:                   A dictionary of objects in the input_attributes to the closest objects in the
                                target_attributes.
    """
    closest_matches = {}

    # for each object in the first set find the objects with the closest target attributes
    for a in input_attributes:
        best_dist = float('inf')
        best_matches = []
        for b in target_attributes:
            dist = _euclidean_dist(input_attributes[a], target_attributes[b])
            if dist < best_dist:
                best_matches = [b]
                best_dist = dist
            elif dist == best_dist:
                best_matches.append(b)
        closest_matches[a] = best_matches

    return closest_matches


# from http://rosettacode.org/wiki/Levenshtein_distance
def _levenshtein_distance(s1, s2):
    """
    :param s1:  A list or string
    :param s2:  Another list or string
    :returns:    The levenshtein distance between the two
    """
    if len(s1) > len(s2):
        s1, s2 = s2, s1
    distances = range(len(s1) + 1)
    for index2, num2 in enumerate(s2):
        new_distances = [index2 + 1]
        for index1, num1 in enumerate(s1):
            if num1 == num2:
                new_distances.append(distances[index1])
            else:
                new_distances.append(1 + min((distances[index1],
                                             distances[index1+1],
                                             new_distances[-1])))
        distances = new_distances
    return distances[-1]


def _normalized_levenshtein_distance(s1, s2, acceptable_differences):
    """
    This function calculates the levenshtein distance but allows for elements in the lists to be different by any number
    in the set acceptable_differences.

    :param s1:                      A list.
    :param s2:                      Another list.
    :param acceptable_differences:  A set of numbers. If (s2[i]-s1[i]) is in the set then they are considered equal.
    :returns:
    """
    if len(s1) > len(s2):
        s1, s2 = s2, s1
        acceptable_differences = set(-i for i in acceptable_differences)
    distances = range(len(s1) + 1)
    for index2, num2 in enumerate(s2):
        new_distances = [index2 + 1]
        for index1, num1 in enumerate(s1):
            if num2 - num1 in acceptable_differences:
                new_distances.append(distances[index1])
            else:
                new_distances.append(1 + min((distances[index1],
                                             distances[index1+1],
                                             new_distances[-1])))
        distances = new_distances
    return distances[-1]


def _is_better_match(x, y, matched_a, matched_b, attributes_dict_a, attributes_dict_b):
    """
    :param x:                   The first element of a possible match.
    :param y:                   The second element of a possible match.
    :param matched_a:           The current matches for the first set.
    :param matched_b:           The current matches for the second set.
    :param attributes_dict_a:   The attributes for each element in the first set.
    :param attributes_dict_b:   The attributes for each element in the second set.
    :returns:                   True/False
    """
    attributes_x = attributes_dict_a[x]
    attributes_y = attributes_dict_b[y]
    if x in matched_a:
        attributes_match = attributes_dict_b[matched_a[x]]
        if _euclidean_dist(attributes_x, attributes_y) >= _euclidean_dist(attributes_x, attributes_match):
            return False
    if y in matched_b:
        attributes_match = attributes_dict_a[matched_b[y]]
        if _euclidean_dist(attributes_x, attributes_y) >= _euclidean_dist(attributes_y, attributes_match):
            return False
    return True


def differing_constants(block_a, block_b):
    """
    Compares two basic blocks and finds all the constants that differ from the first block to the second.

    :param block_a: The first block to compare.
    :param block_b: The second block to compare.
    :returns:       Returns a list of differing constants in the form of ConstantChange, which has the offset in the
                    block and the respective constants.
    """
    statements_a = [s for s in block_a.vex.statements if s.tag != "Ist_IMark"] + [block_a.vex.next]
    statements_b = [s for s in block_b.vex.statements if s.tag != "Ist_IMark"] + [block_b.vex.next]
    if len(statements_a) != len(statements_b):
        raise UnmatchedStatementsException("Blocks have different numbers of statements")

    start_1 = min(block_a.instruction_addrs)
    start_2 = min(block_b.instruction_addrs)

    changes = []

    # check statements
    current_offset = None
    for statement, statement_2 in zip(statements_a, statements_b):
        # sanity check
        if statement.tag != statement_2.tag:
            raise UnmatchedStatementsException("Statement tag has changed")

        if statement.tag == "Ist_IMark":
            if statement.addr - start_1 != statement_2.addr - start_2:
                raise UnmatchedStatementsException("Instruction length has changed")
            current_offset = statement.addr - start_1
            continue

        differences = compare_statement_dict(statement, statement_2)
        for d in differences:
            if d.type != DIFF_VALUE:
                raise UnmatchedStatementsException("Instruction has changed")
            else:
                changes.append(ConstantChange(current_offset, d.value_a, d.value_b))

    return changes


def compare_statement_dict(statement_1, statement_2):
    # should return whether or not the statement's type/effects changed
    # need to return the specific number that changed too

    if type(statement_1) != type(statement_2):
        return [Difference(DIFF_TYPE, None, None)]

    # None
    if statement_1 is None and statement_2 is None:
        return []

    # constants
    if isinstance(statement_1, (int, long, float, str)):
        if isinstance(statement_1, float) and math.isnan(statement_1) and math.isnan(statement_2):
            return []
        elif statement_1 == statement_2:
            return []
        else:
            return [Difference(None, statement_1, statement_2)]

    # tuples/lists
    if isinstance(statement_1, (tuple, list)):
        if len(statement_1) != len(statement_2):
            return Difference(DIFF_TYPE, None, None)

        differences = []
        for s1, s2 in zip(statement_1, statement_2):
            differences += compare_statement_dict(s1, s2)
        return differences

    # Yan's weird types
    differences = []
    for attr in statement_1.__slots__:
        # don't check arch, property, or methods
        if attr == "arch":
            continue
        if hasattr(statement_1.__class__, attr) and isinstance(getattr(statement_1.__class__, attr), property):
            continue
        if isinstance(getattr(statement_1, attr), types.MethodType):
            continue

        new_diffs = compare_statement_dict(getattr(statement_1, attr), getattr(statement_2, attr))
        # set the difference types
        for diff in new_diffs:
            if diff.type is None:
                diff.type = attr
        differences += new_diffs

    return differences


class FunctionDiff(object):
    """
    This class computes the a diff between two functions.
    """
    def __init__(self, bdd_a, bdd_b, function_a, function_b, bindiff=None):
        """
        :param function_a: The first angr Function object to diff.
        :param function_b: The second angr Function object.
        :param bindiff:    An optional Bindiff object. Used for some extra normalization during basic block comparison.
        """
        self._bdd_a = bdd_a
        self._bdd_b = bdd_b
        self._function_a = self._bdd_a.normalized_functions[function_a.addr]
        self._function_b = self._bdd_b.normalized_functions[function_b.addr]
        self._bindiff = bindiff

        self.attributes_a = self._compute_block_attributes(self._function_a)
        self.attributes_b = self._compute_block_attributes(self._function_b)

        self._block_matches = set()
        self._unmatched_blocks_from_a = set()
        self._unmatched_blocks_from_b = set()

        self._compute_diff()

    @property
    def probably_identical(self):
        """
        :returns: Whether or not these two functions are identical.
        """
        if len(self._unmatched_blocks_from_a | self._unmatched_blocks_from_b) > 0:
            return False
        for (a, b) in self._block_matches:
            if not self.blocks_probably_identical(a, b):
                return False
        return True

    @property
    def identical_blocks(self):
        """
        :returns: A list of block matches which appear to be identical
        """
        identical_blocks = []
        for (block_a, block_b) in self._block_matches:
            if self.blocks_probably_identical(block_a, block_b):
                identical_blocks.append((block_a, block_b))
        return identical_blocks

    @property
    def differing_blocks(self):
        """
        :returns: A list of block matches which appear to differ
        """
        differing_blocks = []
        for (block_a, block_b) in self._block_matches:
            if not self.blocks_probably_identical(block_a, block_b):
                differing_blocks.append((block_a, block_b))
        return differing_blocks

    @property
    def blocks_with_differing_constants(self):
        """
        :return: A list of block matches which appear to differ
        """
        differing_blocks = []
        diffs = dict()
        for (block_a, block_b) in self._block_matches:
            if self.blocks_probably_identical(block_a, block_b) and \
                    not self.blocks_probably_identical(block_a, block_b, check_constants=True):
                differing_blocks.append((block_a, block_b))
        for block_a, block_b in differing_blocks:
            ba = self.bdd_a.normalized_blocks[(self._function_a.orig_function.addr, block_a.addr)]
            bb = self.bdd_b.normalized_blocks[(self._function_b.orig_function.addr, block_b.addr)]
            diffs[(block_a, block_b)] = FunctionDiff._block_diff_constants(ba, bb)
        return diffs

    @property
    def block_matches(self):
        return self._block_matches

    @property
    def unmatched_blocks(self):
        return self._unmatched_blocks_from_a, self._unmatched_blocks_from_b

    def block_similarity(self, block_a, block_b):
        """
        :param block_a: The first block address.
        :param block_b: The second block address.
        :returns:       The similarity of the basic blocks, normalized for the base address of the block and function
                        call addresses.
        """

        # handle sim procedure blocks
        if self._bdd_a.is_hooked(block_a) and self._bdd_b.is_hooked(block_b):
            if self._bdd_a._sim_procedures[block_a] == self._bdd_b._sim_procedures[block_b]:
                return 1.0
            else:
                return 0.0

        block_a = self._bdd_a.normalized_blocks[(self._function_a.orig_function.addr, block_a.addr)]
        block_b = self._bdd_b.normalized_blocks[(self._function_b.orig_function.addr, block_b.addr)]

        # if both were None then they are assumed to be the same, if only one was the same they are assumed to differ
        if block_a is None and block_b is None:
            return 1.0
        elif block_a is None or block_b is None:
            return 0.0

        # get all elements for computing similarity
        tags_a = [s.tag for s in block_a.statements]
        tags_b = [s.tag for s in block_b.statements]
        consts_a = [c.value for c in block_a.all_constants]
        consts_b = [c.value for c in block_b.all_constants]
        all_registers_a = [s.offset for s in block_a.statements if hasattr(s, "offset")]
        all_registers_b = [s.offset for s in block_b.statements if hasattr(s, "offset")]
        jumpkind_a = block_a.jumpkind
        jumpkind_b = block_b.jumpkind

        # compute total distance
        total_dist = 0
        total_dist += _levenshtein_distance(tags_a, tags_b)
        total_dist += _levenshtein_distance(block_a.operations, block_b.operations)
        total_dist += _levenshtein_distance(all_registers_a, all_registers_b)
        acceptable_differences = self._get_acceptable_constant_differences(block_a, block_b)
        total_dist += _normalized_levenshtein_distance(consts_a, consts_b, acceptable_differences)
        total_dist += 0 if jumpkind_a == jumpkind_b else 1

        # compute similarity
        num_values = max(len(tags_a), len(tags_b))
        num_values += max(len(consts_a), len(consts_b))
        num_values += max(len(block_a.operations), len(block_b.operations))
        num_values += 1  # jumpkind
        similarity = 1 - (float(total_dist) / num_values)

        return similarity

    def blocks_probably_identical(self, block_a, block_b, check_constants=False):
        """
        :param block_a:         The first block address.
        :param block_b:         The second block address.
        :param check_constants: Whether or not to require matching constants in blocks.
        :returns:               Whether or not the blocks appear to be identical.
        """
        # handle sim procedure blocks
        if self._bdd_a.is_hooked(block_a) and self._bdd_b.is_hooked(block_b):
            return self._bdd_a._sim_procedures[block_a] == self._bdd_b._sim_procedures[block_b]

        block_a = self._bdd_a.normalized_blocks[(self._function_a.orig_function.addr, block_a.addr)]
        block_b = self._bdd_b.normalized_blocks[(self._function_b.orig_function.addr, block_b.addr)]

        # if both were None then they are assumed to be the same, if only one was None they are assumed to differ
        if block_a is None and block_b is None:
            return True
        elif block_a is None or block_b is None:
            return False

        # if they represent a different number of blocks they are not the same
        if len(block_a.blocks) != len(block_b.blocks):
            return False

        # check differing constants
        try:
            diff_constants = FunctionDiff._block_diff_constants(block_a, block_b)
        except UnmatchedStatementsException:
            return False

        if not check_constants:
            return True

        # get values of differences that probably indicate no change
        acceptable_differences = self._get_acceptable_constant_differences(block_a, block_b)

        # todo match globals
        for c in diff_constants:
            if (c.value_a, c.value_b) in self._block_matches:
                # constants point to matched basic blocks
                continue
            if self._bindiff is not None and (c.value_a and c.value_b) in self._bindiff.function_matches:
                # constants point to matched functions
                continue
            # if both are in the binary we'll assume it's okay, although we should really match globals
            # TODO use global matches
            if self._bdd_a.loader.main_object.contains_addr(c.value_a) and \
                    self._bdd_b.loader.main_object.contains_addr(c.value_b):
                continue
            # if the difference is equal to the difference in block addr's or successor addr's we'll say it's also okay
            if c.value_b - c.value_a in acceptable_differences:
                continue
            # otherwise they probably are different
            return False

        # the blocks appear to be identical
        return True

    @staticmethod
    def _block_diff_constants(block_a, block_b):
        diff_constants = []
        for irsb_a, irsb_b in zip(block_a.blocks, block_b.blocks):
            diff_constants += differing_constants(irsb_a, irsb_b)
        return diff_constants

    @staticmethod
    def _compute_block_attributes(function):
        """
        :param function:    A normalized function object.
        :returns:           A dictionary of basic block addresses to tuples of attributes.
        """
        # The attributes we use are the distance form function start, distance from function exit and whether
        # or not it has a subfunction call
        distances_from_start = FunctionDiff._distances_from_function_start(function)
        distances_from_exit = FunctionDiff._distances_from_function_exit(function)
        call_sites = function.call_sites

        attributes = {}
        for block in function.graph.nodes():
            if block in call_sites:
                number_of_subfunction_calls = len(call_sites[block])
            else:
                number_of_subfunction_calls = 0
            # there really shouldn't be blocks that can't be reached from the start, but there are for now
            dist_start = distances_from_start[block] if block in distances_from_start else 10000
            dist_exit = distances_from_exit[block] if block in distances_from_exit else 10000

            attributes[block] = (dist_start, dist_exit, number_of_subfunction_calls)

        return attributes

    @staticmethod
    def _distances_from_function_start(function):
        """
        :param function:    A normalized Function object.
        :returns:           A dictionary of basic block addresses and their distance to the start of the function.
        """
        return networkx.single_source_shortest_path_length(function.graph,
                                                           function.startpoint)

    @staticmethod
    def _distances_from_function_exit(function):
        """
        :param function:    A normalized Function object.
        :returns:           A dictionary of basic block addresses and their distance to the exit of the function.
        """
        reverse_graph = function.graph.reverse()
        # we aren't guaranteed to have an exit from the function so explicitly add the node
        reverse_graph.add_node("start")
        found_exits = False
        for n in function.graph.nodes():
            if len(list(function.graph.successors(n))) == 0:
                reverse_graph.add_edge("start", n)
                found_exits = True

        # if there were no exits (a function with a while 1) let's consider the block with the highest address to
        # be the exit. This isn't the most scientific way, but since this case is pretty rare it should be okay
        if not found_exits:
            last = max(function.graph.nodes(), key=lambda x:x.addr)
            reverse_graph.add_edge("start", last)

        dists = networkx.single_source_shortest_path_length(reverse_graph, "start")

        # remove temp node
        del dists["start"]

        # correct for the added node
        for n in dists:
            dists[n] -= 1

        return dists

    def _compute_diff(self):
        """
        Computes the diff of the functions and saves the result.
        """
        # get the attributes for all blocks
        l.debug("Computing diff of functions: %s, %s",
                ("%#x" % self._function_a.startpoint.addr) if self._function_a.startpoint is not None else "None",
                ("%#x" % self._function_b.startpoint.addr) if self._function_b.startpoint is not None else "None"
                )

        # get the initial matches
        initial_matches = self._get_block_matches(self.attributes_a, self.attributes_b,
                                                  tiebreak_with_block_similarity=False)

        # Use a queue so we process matches in the order that they are found
        to_process = deque(initial_matches)

        # Keep track of which matches we've already added to the queue
        processed_matches = set((x, y) for (x, y) in initial_matches)

        # Keep a dict of current matches, which will be updated if better matches are found
        matched_a = dict()
        matched_b = dict()
        for (x, y) in processed_matches:
            matched_a[x] = y
            matched_b[y] = x

        # while queue is not empty
        while to_process:
            (block_a, block_b) = to_process.pop()
            l.debug("FunctionDiff: Processing (%#x, %#x)", block_a.addr, block_b.addr)

            # we could find new matches in the successors or predecessors of functions
            block_a_succ = list(self._function_a.graph.successors(block_a))
            block_b_succ = list(self._function_b.graph.successors(block_b))
            block_a_pred = list(self._function_a.graph.predecessors(block_a))
            block_b_pred = list(self._function_b.graph.predecessors(block_b))

            # propagate the difference in blocks as delta
            delta = tuple((i-j) for i, j in zip(self.attributes_b[block_b], self.attributes_a[block_a]))

            # get possible new matches
            new_matches = []

            # if the blocks are identical then the successors should most likely be matched in the same order
            if self.blocks_probably_identical(block_a, block_b) and len(block_a_succ) == len(block_b_succ):
                ordered_succ_a = self._get_ordered_successors(self._bdd_a, self._function_a.orig_function.addr,
                                                              block_a, block_a_succ)
                ordered_succ_b = self._get_ordered_successors(self._bdd_b, self._function_b.orig_function.addr,
                                                              block_b, block_b_succ)

                new_matches += zip(ordered_succ_a, ordered_succ_b)

            new_matches += self._get_block_matches(self.attributes_a, self.attributes_b, block_a_succ, block_b_succ,
                                                   delta, tiebreak_with_block_similarity=True)
            new_matches += self._get_block_matches(self.attributes_a, self.attributes_b, block_a_pred, block_b_pred,
                                                   delta, tiebreak_with_block_similarity=True)

            # for each of the possible new matches add it if it improves the matching
            for (x, y) in new_matches:
                if (x, y) not in processed_matches:
                    processed_matches.add((x, y))
                    l.debug("FunctionDiff: checking if (%#x, %#x) is better", x.addr, y.addr)
                    # if it's a better match than what we already have use it
                    if _is_better_match(x, y, matched_a, matched_b, self.attributes_a, self.attributes_b):
                        l.debug("FunctionDiff: adding possible match (%#x, %#x)", x.addr, y.addr)
                        if x in matched_a:
                            old_match = matched_a[x]
                            del matched_b[old_match]
                        if y in matched_b:
                            old_match = matched_b[y]
                            del matched_a[old_match]
                        matched_a[x] = y
                        matched_b[y] = x
                        to_process.appendleft((x, y))

        # reformat matches into a set of pairs
        self._block_matches = set((x, y) for (x, y) in matched_a.items())

        # get the unmatched blocks
        self._unmatched_blocks_from_a = set(x for x in self._function_a.graph.nodes() if x not in matched_a)
        self._unmatched_blocks_from_b = set(x for x in self._function_b.graph.nodes() if x not in matched_b)

    @staticmethod
    def _get_ordered_successors(bdd, faddr, block, succ):
        return bdd.ordered_successors[(faddr, block.addr)]

    def _get_block_matches(self, attributes_a, attributes_b, filter_set_a=None, filter_set_b=None, delta=(0, 0, 0),
                           tiebreak_with_block_similarity=False):
        """
        :param attributes_a:    A dict of blocks to their attributes
        :param attributes_b:    A dict of blocks to their attributes

        The following parameters are optional.

        :param filter_set_a:    A set to limit attributes_a to the blocks in this set.
        :param filter_set_b:    A set to limit attributes_b to the blocks in this set.
        :param delta:           An offset to add to each vector in attributes_a.
        :returns:               A list of tuples of matching objects.
        """
        # get the attributes that are in the sets
        if filter_set_a is None:
            filtered_attributes_a = {k: v for k, v in attributes_a.items()}
        else:
            filtered_attributes_a = {k: v for k, v in attributes_a.items() if k in filter_set_a}

        if filter_set_b is None:
            filtered_attributes_b = {k: v for k, v in attributes_b.items()}
        else:
            filtered_attributes_b = {k: v for k, v in attributes_b.items() if k in filter_set_b}

        # add delta
        for k in filtered_attributes_a:
            filtered_attributes_a[k] = tuple((i+j) for i, j in zip(filtered_attributes_a[k], delta))
        for k in filtered_attributes_b:
            filtered_attributes_b[k] = tuple((i+j) for i, j in zip(filtered_attributes_b[k], delta))

        # get closest
        closest_a = _get_closest_matches(filtered_attributes_a, filtered_attributes_b)
        closest_b = _get_closest_matches(filtered_attributes_b, filtered_attributes_a)

        if tiebreak_with_block_similarity:
            # use block similarity to break ties in the first set
            for a in closest_a:
                if len(closest_a[a]) > 1:
                    best_similarity = 0
                    best = []
                    for x in closest_a[a]:
                        similarity = self.block_similarity(a, x)
                        if similarity > best_similarity:
                            best_similarity = similarity
                            best = [x]
                        elif similarity == best_similarity:
                            best.append(x)
                    closest_a[a] = best

            # use block similarity to break ties in the second set
            for b in closest_b:
                if len(closest_b[b]) > 1:
                    best_similarity = 0
                    best = []
                    for x in closest_b[b]:
                        similarity = self.block_similarity(x, b)
                        if similarity > best_similarity:
                            best_similarity = similarity
                            best = [x]
                        elif similarity == best_similarity:
                            best.append(x)
                    closest_b[b] = best

        # a match (x,y) is good if x is the closest to y and y is the closest to x
        matches = []
        for a in closest_a:
            if len(closest_a[a]) == 1:
                match = closest_a[a][0]
                if len(closest_b[match]) == 1 and closest_b[match][0] == a:
                    matches.append((a, match))

        return matches

    def _get_acceptable_constant_differences(self, block_a, block_b):
        # keep a set of the acceptable differences in constants between the two blocks
        acceptable_differences = set()
        acceptable_differences.add(0)

        block_a_base = block_a.instruction_addrs[0]
        block_b_base = block_b.instruction_addrs[0]
        acceptable_differences.add(block_b_base - block_a_base)

        # get matching successors
        for target_a, target_b in zip(block_a.call_targets, block_b.call_targets):
            # these can be none if we couldn't resolve the call target
            if target_a is None or target_b is None:
                continue
            acceptable_differences.add(target_b - target_a)
            acceptable_differences.add((target_b - block_b_base) - (target_a - block_a_base))

        # get the difference between the data segments
        # this is hackish
        if ".bss" in self._bdd_a.loader.main_object.sections_map and \
                ".bss" in self._bdd_b.loader.main_object.sections_map:
            bss_a = self._bdd_a.loader.main_object.sections_map[".bss"].min_addr
            bss_b = self._bdd_b.loader.main_object.sections_map[".bss"].min_addr
            acceptable_differences.add(bss_b - bss_a)
            acceptable_differences.add((bss_b - block_b_base) - (bss_a - block_a_base))

        return acceptable_differences


class BinDiff(object):
    """
    This class computes the a diff between two binaries represented by BinDiffDescriptors
    """
    def __init__(self, bdd_a, bdd_b,
                 globally_banned_a=frozenset(), globally_banned_b=frozenset(),
                 enable_advanced_backward_slicing=False):
        """
        :param bdd_a: The first BinDiffDescriptor to use
        :param bdd_b: The second BinDiffDescriptor to use
        """
        back_traversal = not enable_advanced_backward_slicing

        self.bdd_a = bdd_a
        self.bdd_b = bdd_b

        self.cfg_a = bdd_a.cfg
        self.cfg_b = bdd_b.cfg

        self.attributes_a = self.bdd_a.function_attributes
        self.attributes_b = self.bdd_b.function_attributes

        self.globally_banned_a = globally_banned_a
        self.globally_banned_b = globally_banned_b

        self._function_diffs = dict()
        self.function_matches = set()
        self._unmatched_functions_from_a = set()
        self._unmatched_functions_from_b = set()

        self._compute_diff()

    def functions_probably_identical(self, func_a_addr, func_b_addr, check_consts=False):
        """
        Compare two functions and return True if they appear identical.

        :param func_a_addr: The address of the first function (in the first binary).
        :param func_b_addr: The address of the second function (in the second binary).
        :returns:           Whether or not the functions appear to be identical.
        """
        if self.bdd_a.is_hooked(func_a_addr) and self.bdd_b.is_hooked(func_b_addr):
            return self.bdd_a._sim_procedures[func_a_addr] == self.bdd_b._sim_procedures[func_b_addr]

        func_diff = self.get_function_diff(func_a_addr, func_b_addr)
        if check_consts:
            return func_diff.probably_identical_with_consts

        return func_diff.probably_identical

    @property
    def identical_functions(self):
        """
        :returns: A list of function matches that appear to be identical
        """
        identical_funcs = []
        for (func_a, func_b) in self.function_matches:
            if self.functions_probably_identical(func_a, func_b):
                identical_funcs.append((func_a, func_b))
        return identical_funcs

    @property
    def differing_functions(self):
        """
        :returns: A list of function matches that appear to differ
        """
        different_funcs = []
        for (func_a, func_b) in self.function_matches:
            if not self.functions_probably_identical(func_a, func_b):
                different_funcs.append((func_a, func_b))
        return different_funcs

    def differing_functions_with_consts(self):
        """
        :return: A list of function matches that appear to differ including just by constants
        """
        different_funcs = []
        for (func_a, func_b) in self.function_matches:
            if not self.functions_probably_identical(func_a, func_b, check_consts=True):
                different_funcs.append((func_a, func_b))
        return different_funcs

    @property
    def differing_blocks(self):
        """
        :returns: A list of block matches that appear to differ
        """
        differing_blocks = []
        for (func_a, func_b) in self.function_matches:
            differing_blocks.extend(self.get_function_diff(func_a, func_b).differing_blocks)
        return differing_blocks

    @property
    def identical_blocks(self):
        """
        :return A list of all block matches that appear to be identical
        """
        identical_blocks = []
        for (func_a, func_b) in self.function_matches:
            identical_blocks.extend(self.get_function_diff(func_a, func_b).identical_blocks)
        return identical_blocks

    @property
    def blocks_with_differing_constants(self):
        """
        :return: A dict of block matches with differing constants to the tuple of constants
        """
        diffs = dict()
        for (func_a, func_b) in self.function_matches:
            diffs.update(self.get_function_diff(func_a, func_b).blocks_with_differing_constants)
        return diffs

    @property
    def unmatched_functions(self):
        return self._unmatched_functions_from_a, self._unmatched_functions_from_b

    # gets the diff of two functions in the binaries
    def get_function_diff(self, function_addr_a, function_addr_b):
        """
        :param function_addr_a: The address of the first function (in the first binary)
        :param function_addr_b: The address of the second function (in the second binary)
        :returns: the FunctionDiff of the two functions
        """
        pair = (function_addr_a, function_addr_b)
        if pair not in self._function_diffs:
            function_a = self.bdd_a.function_manager.function(function_addr_a)
            function_b = self.bdd_b.function_manager.function(function_addr_b)
            self._function_diffs[pair] = FunctionDiff(self.bdd_a, self.bdd_b, function_a, function_b, self)
        return self._function_diffs[pair]

    def _get_call_site_matches(self, func_a, func_b):
        possible_matches = set()

        # Make sure those functions are not SimProcedures
        f_a = self.bdd_a.function_manager.function(func_a)
        f_b = self.bdd_b.function_manager.function(func_b)
        if f_a.startpoint is None or f_b.startpoint is None:
            return possible_matches

        fd = self.get_function_diff(func_a, func_b)
        basic_block_matches = fd.block_matches
        function_a = fd._function_a
        function_b = fd._function_b
        for (a, b) in basic_block_matches:
            if a in function_a.call_sites and b in function_b.call_sites:
                # add them in order
                for target_a, target_b in zip(function_a.call_sites[a], function_b.call_sites[b]):
                    possible_matches.add((target_a, target_b))
                # add them in reverse, since if a new call was added the ordering from each side
                # will remain constant until the change
                for target_a, target_b in zip(reversed(function_a.call_sites[a]),
                                              reversed(function_b.call_sites[b])):
                    possible_matches.add((target_a, target_b))

        return possible_matches

    def _get_plt_matches(self):
        plt_matches = []
        for name, addr in self.bdd_a.loader.main_object.plt.items():
            if name in self.bdd_b.loader.main_object.plt:
                plt_matches.append((addr, self._p2.loader.main_object.plt[name]))

        # remove ones that aren't in the interfunction graph, because these seem to not be consistent
        all_funcs_a = set(self.bdd_a.function_manager.callgraph.nodes())
        all_funcs_b = set(self.bdd_b.function_manager.callgraph.nodes())
        plt_matches = [x for x in plt_matches if x[0] in all_funcs_a and x[1] in all_funcs_b]

        return plt_matches

    def _get_name_matches(self):
        names_to_addrs_a = dict()
        for f in self.bdd_a.function_manager.values():
            if not f.name.startswith("sub_"):
                names_to_addrs_a[f.name] = f.addr

        names_to_addrs_b = dict()
        for f in self.bdd_b.function_manager.values():
            if not f.name.startswith("sub_"):
                names_to_addrs_b[f.name] = f.addr

        name_matches = []
        for name, addr in names_to_addrs_a.items():
            if name in names_to_addrs_b:
                name_matches.append((addr, names_to_addrs_b[name]))

        return name_matches

    def _compute_diff(self):
        # get the initial matches
        initial_matches = []
        # initial_matches += self._get_plt_matches()
        initial_matches += self._get_function_matches(self.attributes_a, self.attributes_b)
        for (a, b) in initial_matches:
            l.debug("Initally matched (%#x, %#x)", a, b)

        # Use a queue so we process matches in the order that they are found
        to_process = deque(initial_matches)

        # Keep track of which matches we've already added to the queue
        processed_matches = set((x, y) for (x, y) in initial_matches)

        # Keep a dict of current matches, which will be updated if better matches are found
        matched_a = dict()
        matched_b = dict()
        for (x, y) in processed_matches:
            matched_a[x] = y
            matched_b[y] = x

        callgraph_a_nodes = set(self.bdd_a.function_manager.callgraph.nodes())
        callgraph_b_nodes = set(self.bdd_b.function_manager.callgraph.nodes())

        # while queue is not empty
        while to_process:
            (func_a, func_b) = to_process.pop()
            l.debug("Processing (%#x, %#x)", func_a, func_b)

            # we could find new matches in the successors or predecessors of functions
            if not self.bdd_a.loader.main_object.contains_addr(func_a):
                continue
            if not self.bdd_a.loader.main_object.contains_addr(func_b):
                continue

            func_a_succ = self.bdd_a.function_manager.callgraph.successors(func_a) if func_a in callgraph_a_nodes else []
            func_b_succ = self.bdd_b.function_manager.callgraph.successors(func_b) if func_b in callgraph_b_nodes else []
            func_a_pred = self.bdd_a.function_manager.callgraph.predecessors(func_a) if func_a in callgraph_a_nodes else []
            func_b_pred = self.bdd_b.function_manager.callgraph.predecessors(func_b) if func_b in callgraph_b_nodes else []

            # get possible new matches
            new_matches = set(self._get_function_matches(self.attributes_a, self.attributes_b,
                                                         func_a_succ, func_b_succ))
            new_matches |= set(self._get_function_matches(self.attributes_a, self.attributes_b,
                                                          func_a_pred, func_b_pred))

            # could also find matches as function calls of matched basic blocks
            new_matches.update(self._get_call_site_matches(func_a, func_b))

            # for each of the possible new matches add it if it improves the matching
            for (x, y) in new_matches:
                # skip none functions and syscalls
                if self.bdd_a.function_manager.function(x) is None or self.bdd_a.function_manager.function(x).is_syscall:
                    continue
                if self.bdd_b.function_manager.function(y) is None or self.bdd_b.function_manager.function(y).is_syscall:
                    continue

                if (x, y) not in processed_matches:
                    processed_matches.add((x, y))
                    # if it's a better match than what we already have use it
                    l.debug("Checking function match %s, %s", hex(x), hex(y))
                    if _is_better_match(x, y, matched_a, matched_b, self.attributes_a, self.attributes_b):
                        l.debug("Adding potential match %s, %s", hex(x), hex(y))
                        if x in matched_a:
                            old_match = matched_a[x]
                            del matched_b[old_match]
                            l.debug("Removing previous match (%#x, %#x)", x, old_match)
                        if y in matched_b:
                            old_match = matched_b[y]
                            del matched_a[old_match]
                            l.debug("Removing previous match (%#x, %#x)", old_match, y)
                        matched_a[x] = y
                        matched_b[y] = x
                        to_process.appendleft((x, y))

        # reformat matches into a set of pairs
        self.function_matches = set()
        for x,y in matched_a.items():
            # only keep if the pair is in the binary ranges
            if self.bdd_a.loader.main_object.contains_addr(x) and self.bdd_b.loader.main_object.contains_addr(y):
                self.function_matches.add((x, y))

        # get the unmatched functions
        self._unmatched_functions_from_a = set(x for x in self.attributes_a.keys() if x not in matched_a)
        self._unmatched_functions_from_b = set(x for x in self.attributes_b.keys() if x not in matched_b)

        # remove unneeded function diffs
        for (x, y) in dict(self._function_diffs):
            if (x, y) not in self.function_matches:
                del self._function_diffs[(x, y)]

    def lib_result_stats(self):
        smaller = min((self.bdd_a, self.bdd_b), key=lambda x: len(x.function_manager))
        bigger = max((self.bdd_a, self.bdd_b), key=lambda x: len(x.function_manager))

        needs_reverse = smaller != self.bdd_a
        matched = [t[::(-1 if needs_reverse else 1)] for t in self.function_matches]
        globally_banned_smaller, _ = (self.globally_banned_a, self.globally_banned_b)[::-1 if needs_reverse else 1]

        named = [LibMatch(t[1], t[0], smaller.function_manager.function(t[0]).name, smaller.filename)
                 for t in matched]

        # import ipdb; ipdb.set_trace()

        allowed_funcs = set(smaller.function_manager.keys()) - globally_banned_smaller

        r = float(len(named)) / float(len(allowed_funcs))
        return r, named

    def _get_function_matches(self, attributes_a, attributes_b, filter_set_a=None, filter_set_b=None):
        """
        :param attributes_a:    A dict of functions to their attributes
        :param attributes_b:    A dict of functions to their attributes

        The following parameters are optional.

        :param filter_set_a:    A set to limit attributes_a to the functions in this set.
        :param filter_set_b:    A set to limit attributes_b to the functions in this set.
        :returns:               A list of tuples of matching objects.
        """
        # get the attributes that are in the sets
        if filter_set_a is None:
            filtered_attributes_a = {k: v for k, v in attributes_a.items()
                                     if k not in self.globally_banned_a}
        else:
            filtered_attributes_a = {k: v for k, v in attributes_a.items()
                                     if k in filter_set_a and k not in self.globally_banned_a}

        if filter_set_b is None:
            filtered_attributes_b = {k: v for k, v in attributes_b.items()
                                     if k not in self.globally_banned_b}
        else:
            filtered_attributes_b = {k: v for k, v in attributes_b.items()
                                     if k in filter_set_b and k not in self.globally_banned_b}

        # import ipdb; ipdb.set_trace()

        # get closest
        closest_a = _get_closest_matches(filtered_attributes_a, filtered_attributes_b)
        closest_b = _get_closest_matches(filtered_attributes_b, filtered_attributes_a)

        # a match (x,y) is good if x is the closest to y and y is the closest to x
        matches = []
        for a in closest_a:
            """
            if len(closest_a[a]) == 1:
                match = closest_a[a][0]
                if len(closest_b[match]) == 1 and closest_b[match][0] == a:
                    matches.append((a, match))
            """
            for b in closest_a[a]:
                if a in closest_b[b]:
                    matches.append((a, b))

        return matches
