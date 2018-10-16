import subprocess
import os
import sys
import angr
import cle
import base64

# This is a really gross py3+angr to IDA bridge.  Replace with idalink, someday

def ida_it(project, script_name="ida_decomp.py"):
    """
    "IDA it" and return the decompilation results
    :param project: An angr project
    :return:
    """
    cur_file = os.path.abspath(__file__)
    cur_dir = os.path.dirname(cur_file)
    script_path = os.path.join(cur_dir, script_name)

    ida_cmd = ['idat',
               '-a-', # enable auto-analysis
               '-B',
               '-c',
               '-S%s' % script_path]
    if type(project.loader.main_object) == cle.backends.elf.elf.ELF:
        # Just do it, IDA will figure it out
        ida_cmd.append(project.filename)
    else:
        # TODO: blob carving
        raise NotImplementedError()

    print(ida_cmd)
    os.system(" ".join(ida_cmd))
    out = {}
    with open("/tmp/ida_out.txt", 'rb') as f:
        crap = f.read()
        for line in crap.splitlines():
            if line.startswith(b"done"):
                break
            addr, pseudo, prime, hash1, hash2, hash3 = line.split(b'\t')
            addr = int(addr, 16)
            pseudo = base64.b64decode(pseudo)
            prime = int(prime)
            out[addr] = (pseudo, prime, hash1, hash2, hash3)
    return out


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
    return 0

#-----------------------------------------------------------------------
def real_quick_ratio(buf1, buf2):
  try:
    if buf1 is None or buf2 is None or buf1 == "" or buf1 == "":
      return 0
    s = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
    return s.real_quick_ratio()
  except:
    return 0

#-----------------------------------------------------------------------
def ast_ratio(ast1, ast2):
  if ast1 == ast2:
    return 1.0
  elif ast1 is None or ast2 is None:
    return 0
  return difference_ratio(decimal.Decimal(ast1), decimal.Decimal(ast2))

#-----------------------------------------------------------------------

def pseudo_ratio(pseudo1, pseudo2):
    fratio = quick_ratio
    v1 = fratio(pseudo1, pseudo2)
    v1 = float(decimal_values.format(v1))
    if v1 == 1.0:
        # If real_quick_ratio returns 1 try again with quick_ratio
        # because it can result in false positives. If real_quick_ratio
        # says 'different', there is no point in continuing.
        if fratio == real_quick_ratio:
            v1 = quick_ratio(tmp1, tmp2)
            if v1 == 1.0:
                return 1.0


if __name__ == '__main__':
    p = angr.Project(sys.argv[1])
    stuff = ida_it(p)
    for addr, crap in stuff.items():
        pseudo, prime, hash1, hash2, hash3 = crap
        print("%#08x" % addr)
        print("####################################################")
        print(pseudo)
        print("######")
        print("Prime %x" % prime)
        print("Hash1: %s" % hash1)
        print("Hash2: %s" % hash2)
        print("Hash3: %s" % hash3)
        print("\n\n")
