import ctypes
import idc

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
}

# all registered structures; key: name, value: (tid, size)
_registered_structures = {}


def register_struct(objname, s):
    """Registers a ctypes.Structure structure and returns Structure Type ID"""
    tid = idc.AddStruc(-1, objname)
    if tid < 0:
        raise Exception('ida_add_structure error %d' % tid)

    for name, typ in s._fields_:
        if typ in _ctypes_table:
            typ, size = _ctypes_table[typ]
            typeid = -1
        else:
            typ = idc.FF_0OFF
            _, size = _registered_structures[objname]
            typeid = 0

        ret = idc.AddStrucMember(tid,
                                 name,
                                 -1,
                                 typ | idc.FF_DATA,
                                 typeid,
                                 size)
        if ret < 0:
            raise Exception('Error adding member %s: %d' % (name, ret))

    # add this structure identifier to the global list
    _registered_structures[objname] = tid, ctypes.sizeof(s)
    return tid
