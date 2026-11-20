# ========================================================================== #
#                                                                            #
#    KVMD - The main PiKVM daemon.                                           #
#                                                                            #
#    Copyright (C) 2018-2024  Maxim Devaev <mdevaev@gmail.com>               #
#                                                                            #
#    This program is free software: you can redistribute it and/or modify    #
#    it under the terms of the GNU General Public License as published by    #
#    the Free Software Foundation, either version 3 of the License, or       #
#    (at your option) any later version.                                     #
#                                                                            #
# ========================================================================== #

"""Attach MCP to a precompiled RMQ1 KVMD server without replacing vendor code.

Firmware builds based on this source should use the direct registration in
``apps.kvmd.server``. This hook is for an on-device installation where the
vendor's precompiled server differs from this checkout but retains KVMD's
standard constructor arguments and API/subsystem lists.
"""

import inspect

from . import server
from .api.mcp import McpApi


_SERVER_CLASS = server.KvmdServer
if not getattr(_SERVER_CLASS, "_mcp_bootstrap_installed", False):
    _original_init = _SERVER_CLASS.__init__

    def _init_with_mcp(self, *args, **kwargs):
        _original_init(self, *args, **kwargs)
        bound = inspect.signature(_original_init).bind(self, *args, **kwargs).arguments
        api = McpApi(
            bound["hid"],
            bound["atx"],
            bound["msd"],
            bound["streamer"],
            bound["keymap_path"],
        )
        self._KvmdServer__apis.append(api)
        self._KvmdServer__subsystems.append(server._Subsystem.make(api, "MCP controller"))

    _SERVER_CLASS.__init__ = _init_with_mcp
    _SERVER_CLASS._mcp_bootstrap_installed = True
