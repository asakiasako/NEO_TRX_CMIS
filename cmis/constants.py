import enum
from types import MappingProxyType
from collections import namedtuple

@ enum.unique
class HW_TYPE(enum.Enum):
    OSFP = 0
    QSFP_DD = 1
    QSFP = 2
    COBO = 3


HwSigPin = namedtuple('HwSigPin', 'pin_name writtable')
# pin_name: name of hardware signal pin, exactly the same as defined in
# corresponding form factor specification.
# writtable: if hardware signal can be set.

GenericSigMap = namedtuple('GenericSigMap', 'ResetL Interrupt LPMode')
# Mapping CMIS generic signal names to form factor specific signal names.
# definition: (pin_name, logical_pol), ref to PIN_MAPS below for example.
# logical_pol = True means the 'CMIS generic name' and the 'form factor signal name' 
# has the same active polarization, i.e. both active high or both active low.
# Ref to 'CMIS specification rev4.0, Appendix A' for detail.

HW_SIG_PINS = MappingProxyType({
    HW_TYPE.OSFP: MappingProxyType({
        'RSTn': HwSigPin('RSTn', writtable=True),
        'INT': HwSigPin('INT', writtable=False),
        'LPWn': HwSigPin('LPWn', writtable=True),
        'PRSn': HwSigPin('PRSn', writtable=False),
    }),
    HW_TYPE.QSFP_DD: MappingProxyType({
        'ResetL': HwSigPin('ResetL', writtable=True),
        'LPMode': HwSigPin('LPMode', writtable=True),
        'ModPrsL': HwSigPin('LPMode', writtable=False),
        'IntL': HwSigPin('IntL', writtable=False),
    }),
    HW_TYPE.QSFP: MappingProxyType({
        # TBD
    }),
    HW_TYPE.COBO: MappingProxyType({
        # TBD
    }),
})

GENERIC_SIG_MAPS = MappingProxyType({
    # pin-maps for different module type
    # Ref to 'CMIS specification rev4.0, Appendix A'
    HW_TYPE.OSFP: GenericSigMap(
        ResetL=('RSTn', True),
        Interrupt=('INT', True),
        LPMode=('LPWn', False)
    ),
    HW_TYPE.QSFP_DD: GenericSigMap(
        ResetL=('ResetL', True),
        Interrupt=('IntL', False),
        LPMode=('LPMode', True)
    ),
    HW_TYPE.QSFP: GenericSigMap(
        ResetL=('ResetL', True),
        Interrupt=('IntL', False),
        LPMode=('LPMode', True)
    ),
    HW_TYPE.COBO: GenericSigMap(
        ResetL=('ResetL', True),
        Interrupt=('IntL', False),
        LPMode=('LPMode', True)
    ),
})