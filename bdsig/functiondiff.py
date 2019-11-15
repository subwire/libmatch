import networkx
import logging
import types
import math
from collections import deque


l = logging.getLogger("bdsig.functiondiff")
l.setLevel("INFO")


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
    if isinstance(statement_1, (int, bytes, float, str)):
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
    def __init__(self, lmd_a, lmd_b, function_a, function_b):
        """
        :param lmd_a: The first LMD (owns function_a)
        :param lmd_b: The second LMD (owns function_b)
        :param function_a: The first NormalizedFunction object
        :param function_b: The second NormalizedFunction object
        """
        self.lmd_a = lmd_a
        self.lmd_b = lmd_b
        self.function_a = function_a
        self.function_b = function_b

        self.attributes_a = self._compute_block_attributes(self.function_a)
        self.attributes_b = self._compute_block_attributes(self.function_b)

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
            if not self.blocks_probably_identical(a, b, check_constants=True):
                return False
        return True

    @property
    def similarity_score(self):
        """
        Return the mean similarity for all matched blocks in the function
        """
        score = 0.0
        n = 0
        for b1, b2 in self._block_matches:
            score += self.block_similarity(b1, b2)
            n += 1
        return score / n

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
            ba = self.lmd_a.normalized_blocks[(self.function_a.addr, block_a.addr)]
            bb = self.lmd_b.normalized_blocks[(self.function_b.addr, block_b.addr)]
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
        if self.lmd_a.is_hooked(block_a) and self.lmd_b.is_hooked(block_b):
            if self.lmd_a._sim_procedures[block_a] == self.lmd_b._sim_procedures[block_b]:
                return 1.0
            else:
                return 0.0

        block_a = self.lmd_a.normalized_blocks[(self.function_a.addr, block_a.addr)]
        block_b = self.lmd_b.normalized_blocks[(self.function_b.addr, block_b.addr)]

        # if both were None then they are assumed to be the same, if only one was the same they are assumed to differ
        if block_a is None and block_b is None:
            return 1.0
        elif block_a is None or block_b is None:
            return 0.0

        # get all elements for computing similarity
        tags_a = [s.tag for s in block_a.statements]
        tags_b = [s.tag for s in block_b.statements]
        consts_a = [c.value for c in block_a.all_constants if not self.lmd_a.loader.main_object.contains_addr(c.value)]
        consts_b = [c.value for c in block_b.all_constants if not (self.lmd_b.loader.min_addr <= c.value < self.lmd_b.loader.max_addr)]
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
        if self.lmd_a.is_hooked(block_a) and self.lmd_b.is_hooked(block_b):
            return self.lmd_a._sim_procedures[block_a] == self.lmd_b._sim_procedures[block_b]

        block_a = self.lmd_a.normalized_blocks[(self.function_a.addr, block_a.addr)]
        block_b = self.lmd_b.normalized_blocks[(self.function_b.addr, block_b.addr)]

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

        for c in diff_constants:
            if (c.value_a, c.value_b) in self._block_matches:
                # constants point to matched basic blocks
                continue
            # if both are in the binary we'll assume it's okay, although we should really match globals
            # TODO use global matches
            if self.lmd_a.loader.main_object.contains_addr(c.value_a) and \
                    self.lmd_b.loader.main_object.contains_addr(c.value_b):
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
                ("%#x" % self.function_a.startpoint.addr) if self.function_a.startpoint is not None else "None",
                ("%#x" % self.function_b.startpoint.addr) if self.function_b.startpoint is not None else "None"
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
            block_a_succ = list(self.function_a.graph.successors(block_a))
            block_b_succ = list(self.function_b.graph.successors(block_b))
            block_a_pred = list(self.function_a.graph.predecessors(block_a))
            block_b_pred = list(self.function_b.graph.predecessors(block_b))

            # propagate the difference in blocks as delta
            delta = tuple((i-j) for i, j in zip(self.attributes_b[block_b], self.attributes_a[block_a]))

            # get possible new matches
            new_matches = []

            # if the blocks are identical then the successors should most likely be matched in the same order
            if self.blocks_probably_identical(block_a, block_b) and len(block_a_succ) == len(block_b_succ):
                ordered_succ_a = self._get_ordered_successors(self.lmd_a, self.function_a.addr,
                                                              block_a, block_a_succ)
                ordered_succ_b = self._get_ordered_successors(self.lmd_b, self.function_b.addr,
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
        self._unmatched_blocks_from_a = set(x for x in self.function_a.graph.nodes() if x not in matched_a)
        self._unmatched_blocks_from_b = set(x for x in self.function_b.graph.nodes() if x not in matched_b)

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
        if not block_a.instruction_addrs or not block_b.instruction_addrs:
            return []
        try:
            block_a_base = block_a.instruction_addrs[0]
        except:
            import ipdb; ipdb.set_trace()
        try:
            block_b_base = block_b.instruction_addrs[0]
        except:
            import ipdb; ipdb.set_trace()
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
        #if ".bss" in self.lmd_a.loader.main_object.sections_map and \
        #        ".bss" in self.lmd_b.loader.main_object.sections_map:
        #    bss_a = self.lmd_a.loader.main_object.sections_map[".bss"].min_addr
        #    bss_b = self.lmd_b.loader.main_object.sections_map[".bss"].min_addr
        #    acceptable_differences.add(bss_b - bss_a)
        #    acceptable_differences.add((bss_b - block_b_base) - (bss_a - block_a_base))

        return acceptable_differences
