""" VarDef for version"""

def versioning_var_defs(
        name = None):  # @unused but required by buildifier
    native.vardef("COPYRIGHT_YEAR", "2022")

    # LINT.IfChange
    native.vardef("VERSION", "1.0.2000.9")
    # LINT.ThenChange(
    #     //depot/google3/subscriptions/flutter/desktop/windows/build_defs.bzl
    # )
