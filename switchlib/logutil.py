"""Cisco-style mnemonic logging ('%FACILITY-SEVERITY-MNEMONIC: message') used
throughout the switch, layered on top of the standard logging module."""

import logging


LOG = logging.getLogger('tap_jsonserver')

# Cisco-IOS-style syslog severity numbers, used only in the rendered message
# text ('%FACILITY-N-MNEMONIC: ...') - actual filtering still goes through
# Python's own logging levels/handlers.
_SEVERITY = {
    logging.DEBUG: 7,
    logging.INFO: 6,
    logging.WARNING: 4,
    logging.ERROR: 3,
    logging.CRITICAL: 2,
}


def log_event(level, facility, mnemonic, message, *args):
    """Emit a switch-style mnemonic log line, e.g. '%PORTSEC-4-MACCONFLICT: ...'.
    message/args follow %-style logging conventions so formatting is skipped
    entirely when `level` is below the configured threshold.

    Whether the leading '%' needs to be doubled depends on whether logging
    will run its own %-substitution pass at all: it only does so when args
    is non-empty (LogRecord.getMessage() skips it entirely for an empty
    args tuple), so an un-doubled '%' would otherwise reach the log verbatim.
    """
    if not LOG.isEnabledFor(level):
        # Skip the tag formatting below too - this runs on the per-frame,
        # per-destination hot path at DEBUG, so it shouldn't cost anything
        # when DEBUG logging is off (the default).
        return
    tag = "%s-%d-%s: " % (facility, _SEVERITY[level], mnemonic)
    if args:
        LOG.log(level, "%%" + tag + message, *args)
    else:
        LOG.log(level, "%" + tag + message)
