from .transceivers import OSFP, QsfpDD

__version__ = '0.2.0'

TRX_MAP = {
    'OSFP': OSFP,
    'QSFP-DD': QsfpDD,
}
