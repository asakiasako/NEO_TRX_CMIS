from . import ain, aout, din, dout

__all__ = ['id_maps']

id_maps = {
    'ain': ain.pin_ID_list,
    'aout': aout.pin_ID_list,
    'din': din.pin_ID_list,
    'dout': dout.pin_ID_list
}