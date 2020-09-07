from .cmis_trx_base import CMISTrxBase
from ..cmis import CMIS, HW_TYPE

class OSFP(CMIS, CMISTrxBase):
    def __init__(self, ip):
        CMIS.__init__(self, HW_TYPE.OSFP)
        CMISTrxBase.__init__(self, ip)

    def get_pin_state(self, pin_name):
        """
        pin_name: str, pin name defined in corresponding HW spec
        return: bool, True for high pin level and False for low pin level
        NOTE: for osfp, pin signals on hostboard are not consistent with those in module.
              so they may have different name & polarization.
        """
        if pin_name not in self.hw_pin:
            raise ValueError('Invalid pin-name.')
        pin_map = {
            # pin_name: (d_name, category, polarization)
            'LPWn': ('MCU_MOD_LPWN', 'dout', False),  # pin use confirmed with Ming Su
            'RSTn': ('MCU_MOD_RSTN', 'dout', True),  # pin use confirmed with Ming Su
            'PRSn': ('H_PRSN', 'din', True),
            'INT': ('H_INTN', 'din', False),
        }
        d_name, cat, pol = pin_map[pin_name]
        state = (not self.get_din(d_name) ^ pol) if cat == 'din' else (not self.get_dout(d_name) ^ pol)
        return state

    def set_pin_state(self, pin_name, is_high_level):
        """
        pin_name: str, pin name defined in corresponding HW spec
        is_high_level: bool, True for high pin level and False for low pin level
        """
        if pin_name not in self.hw_pin:
            raise ValueError('Invalid pin-name.')
        if self.hw_pin[pin_name].writtable == False:
            raise PermissionError('Pin {pin} is not writtable.'.format(pin=pin_name))
        if not isinstance(is_high_level, bool):
            raise TypeError('Parameter is_high_level should be bool.')
        pin_dout_map = {
            'LPWn': ('MCU_MOD_LPWN', False) # pin use confirmed with Ming Su
            'RSTn': ('MCU_MOD_RSTN', True)  # pin use confirmed with Ming Su
        }
        self.set_dout(pin_dout_map[pin_name][0], not is_high_level ^ pin_dout_map[pin_name][1])