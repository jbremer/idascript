import ctypes
import idc

MAX_STRING_LENGTH = 1024

# table to convert ctypes types to IDA types
_ctypes_table = {
    ctypes.c_bool: (idc.FF_BYTE, 1),
    ctypes.c_char: (idc.FF_BYTE, 1),
    ctypes.c_wchar: (idc.FF_WORD, 2),
    ctypes.c_byte: (idc.FF_BYTE, 1),
    ctypes.c_ubyte: (idc.FF_BYTE, 1),
    ctypes.c_short: (idc.FF_WORD, 2),
    ctypes.c_ushort: (idc.FF_WORD, 2),
    ctypes.c_int: (idc.FF_DWRD, 4),
    ctypes.c_uint: (idc.FF_DWRD, 4),
    ctypes.c_long: (idc.FF_DWRD, 4),
    ctypes.c_ulong: (idc.FF_DWRD, 4),
    ctypes.c_float: (idc.FF_FLOAT, 4),
    ctypes.c_double: (idc.FF_DOUBLE, 8),
    ctypes.c_char_p: (idc.FF_0OFF | idc.FF_DWRD, 4),
    ctypes.c_wchar_p: (idc.FF_0OFF | idc.FF_DWRD, 4),
}

# all registered structures; key: type, value: (name, tid, size)
_registered_structures = {}


def _struct_by_name(objname):
    for x, (name, _, _) in _registered_structures.items():
        if objname == name:
            return x
    raise Exception('Structure not found: %s' % objname)


def register_struct(objname, s):
    """Registers a ctypes.Structure structure and returns Structure Type ID"""
    tid = idc.AddStruc(-1, objname)
    if tid < 0:
        raise Exception('ida_add_structure error %d' % tid)

    for name, typ in s._fields_:
        # normal type
        if typ in _ctypes_table:
            typ, size = _ctypes_table[typ]
            typeid = -1
        # embedded struct type
        elif typ in _registered_structures:
            _, typeid, size = _registered_structures[typ]
            typ = idc.FF_STRU
        # pointer to a predefined structure
        else:
            typ = idc.FF_0OFF | idc.FF_DWRD
            typeid, size = 0, 4

        ret = idc.AddStrucMember(tid, name, -1, typ, typeid, size)
        if ret < 0:
            raise Exception('ida_add_structure_member %s: %d' % (name, ret))

    # add this structure identifier to the global list
    _registered_structures[s] = objname, tid, ctypes.sizeof(s)
    return tid


def make_str(address):
    """Calculate the length, undefine and make an ascii string."""
    # calculate the length, with a hardcoded maximum length
    for offset in xrange(MAX_STRING_LENGTH):
        if not idc.GetOriginalByte(address + offset):
            break

    idc.MakeUnknown(address, offset, idc.DOUNK_SIMPLE)
    idc.MakeStr(address, address + offset)


def apply_struct(objname, address):
    """Apply a Structure to an address."""
    structure = _struct_by_name(objname)
    size = ctypes.sizeof(structure)

    # it is known
    idc.MakeUnknown(address, size, idc.DOUNK_SIMPLE)
    idc.MakeStruct(address, objname)

    offset = 0
    for name, typ in structure._fields_:
        # pointer to an ascii string
        if typ == ctypes.c_char_p:
            value = idc.Dword(address + offset)
            make_str(value)
        # pointer to an unicode string
        elif typ == ctypes.c_wchar_p:
            # TODO implement unicode string stuff
            pass

        offset += ctypes.sizeof(typ)

    # read the structure and return that data
    data = (idc.GetOriginalByte(x) for x in xrange(address, address + size))
    return structure.from_buffer_copy(''.join(chr(x) for x in data))
