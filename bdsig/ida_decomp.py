
import os
import re
import sys
import time
import decimal
import base64

from cStringIO import StringIO
from difflib import SequenceMatcher

from jkutils.kfuzzy import CKoretFuzzyHashing
kfh = CKoretFuzzyHashing()

from jkutils.factor import (FACTORS_CACHE, difference, difference_ratio,
                            primesbelow as primes)
import idaapi
import idc
from idc import *
from idaapi import init_hexrays_plugin
from idaapi import *
from idautils import *


# Used to clean-up the pseudo-code and assembly dumps in order to get
# better comparison ratios
CMP_REPS = ["loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
  "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
  "stru_", "dbl_", "locret_"]
CMP_REMS = ["dword ptr ", "byte ptr ", "word ptr ", "qword ptr ", "short ptr"]


#-----------------------------------------------------------------------
class CAstVisitor(ctree_visitor_t):
  def __init__(self, cfunc):
    self.primes = primes(4096)
    ctree_visitor_t.__init__(self, CV_FAST)
    self.cfunc = cfunc
    self.primes_hash = 1
    return

  def visit_expr(self, expr):
    try:
      self.primes_hash *= self.primes[expr.op]
    except:
      traceback.print_exc()
    return 0

  def visit_insn(self, ins):
    try:
      self.primes_hash *= self.primes[ins.op]
    except:
      traceback.print_exc()
    return 0


#-----------------------------------------------------------------------
def result_iter(cursor, arraysize=1000):
  'An iterator that uses fetchmany to keep memory usage down'
  while True:
    results = cursor.fetchmany(arraysize)
    if not results:
      break
    for result in results:
      yield result

#-----------------------------------------------------------------------
def quick_ratio(buf1, buf2):
  try:
    if buf1 is None or buf2 is None or buf1 == "" or buf1 == "":
      return 0
    s = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
    return s.quick_ratio()
  except:
    print "quick_ratio:", str(sys.exc_info()[1])
    return 0

#-----------------------------------------------------------------------
def real_quick_ratio(buf1, buf2):
  try:
    if buf1 is None or buf2 is None or buf1 == "" or buf1 == "":
      return 0
    s = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
    return s.real_quick_ratio()
  except:
    print "real_quick_ratio:", str(sys.exc_info()[1])
    return 0

#-----------------------------------------------------------------------
def ast_ratio(ast1, ast2):
  if ast1 == ast2:
    return 1.0
  elif ast1 is None or ast2 is None:
    return 0
  return difference_ratio(decimal.Decimal(ast1), decimal.Decimal(ast2))

#-----------------------------------------------------------------------

def log(msg):
  print "[%s] %s\n" % (time.asctime(), msg);


def log_refresh(msg, show=False):
  log(msg)

def prettify_asm(asm_source):
  asm = []
  for line in asm_source.split("\n"):
      if not line.startswith("loc_"):
          asm.append("\t" + line)
      else:
          asm.append(line)
  return "\n".join(asm)

re_cache = {}

def re_sub(text, repl, string):
  if text not in re_cache:
      re_cache[text] = re.compile(text, flags=re.IGNORECASE)

  re_obj = re_cache[text]
  return re_obj.sub(repl, string)

def get_cmp_asm_lines(asm):
  sio = StringIO(asm)
  lines = []
  get_cmp_asm = get_cmp_asm
  for line in sio.readlines():
      line = line.strip("\n")
      lines.append(get_cmp_asm(line))
  return "\n".join(lines)

def get_cmp_pseudo_lines(pseudo):
  if pseudo is None:
      return pseudo

  # Remove all the comments
  tmp = re_sub(" // .*", "", pseudo)

  # Now, replace sub_, byte_, word_, dword_, loc_, etc...
  for rep in CMP_REPS:
      tmp = re_sub(rep + "[a-f0-9A-F]+", rep + "XXXX", tmp)
  tmp = re_sub("v[0-9]+", "vXXX", tmp)
  tmp = re_sub("a[0-9]+", "aXXX", tmp)
  tmp = re_sub("arg_[0-9]+", "aXXX", tmp)
  return tmp

def get_cmp_asm(asm):
  if asm is None:
      return asm

  # Ignore the comments in the assembly dump
  tmp = asm.split(";")[0]
  tmp = tmp.split(" # ")[0]
  # Now, replace sub_, byte_, word_, dword_, loc_, etc...
  for rep in CMP_REPS:
      tmp = re_sub(rep + "[a-f0-9A-F]+", "XXXX", tmp)

  # Remove dword ptr, byte ptr, etc...
  for rep in CMP_REMS:
      tmp = re_sub(rep + "[a-f0-9A-F]+", "", tmp)

  reps = ["\+[a-f0-9A-F]+h\+"]
  for rep in reps:
      tmp = re_sub(rep, "+XXXX+", tmp)
  tmp = re_sub("\.\.[a-f0-9A-F]{8}", "XXX", tmp)

  # Strip any possible remaining white-space character at the end of
  # the cleaned-up instruction
  tmp = re_sub("[ \t\n]+$", "", tmp)

  # Replace aName_XXX with aXXX, useful to ignore small changes in
  # offsets created to strings
  tmp = re_sub("a[A-Z]+[a-z0-9]+_[0-9]+", "aXXX", tmp)

  return tmp


def decompile_and_get(ea):
    """
    For a given function EA, return the comparable decompiled result
    :param self:
    :param ea: the EA of the function
    :return: (pseudocode text, pseudocode hash, pseudocode comments)
    """
    decompiler_plugin = "hexarm"
    if not idaapi.init_hexrays_plugin() and not (load_plugin(decompiler_plugin) and idaapi.init_hexrays_plugin()):
      raise Exception("Could not load Hex-Rays!")
    f = get_func(ea)
    if f is None:
      return None, None, None

    cfunc = decompile(f);
    if cfunc is None:
      # Failed to decompile
      return None, None, None

    visitor = CAstVisitor(cfunc)
    visitor.apply_to(cfunc.body, None)
    pseudo_hash = visitor.primes_hash

    cmts = idaapi.restore_user_cmts(cfunc.entry_ea)
    pseudo_comments = {}
    if cmts is not None:
      for tl, cmt in cmts.iteritems():
        pseudo_comments[tl.ea - self.get_base_address()] = [str(cmt), tl.itp]

    sv = cfunc.get_pseudocode()
    pseudo = []
    first_line = None
    for sline in sv:
      line = tag_remove(sline.line)
      if line.startswith("//"):
        continue

      if first_line is None:
        first_line = line
      else:
        pseudo.append(line)
    pseudo_text = "\n".join(pseudo)
    if pseudo_text:
        pseudo_text = get_cmp_pseudo_lines(pseudo_text)
    return pseudo_text, pseudo_hash, pseudo_comments

def get_all_decomp_hashes(outfn):
    with open(outfn, 'wb') as f:
        for segea in Segments():
            for funcea in Functions(segea, SegEnd(segea)):
                try:
                    pseudo_text, pseudo_prime, pseudo_comments = decompile_and_get(funcea)
                    pseudo_hash1, pseudo_hash2, pseudo_hash3 = kfh.hash_bytes(pseudo_text).split(";")
                    pseudo_text = base64.b64encode(pseudo_text)
                    f.write("%#08x\t%s\t%s\t%s\t%s\t%s\n" % (funcea, pseudo_text, pseudo_prime, pseudo_hash1, pseudo_hash2, pseudo_hash3))
                except:
                    raise
        f.write("done\n")

def wait_for_analysis_to_finish():
    idaapi.autoWait()
    idc.Wait()

if __name__ == '__main__':
    outfn = '/tmp/ida_out.txt'
    wait_for_analysis_to_finish()
    get_all_decomp_hashes(outfn)
    Exit(0)