# idaAiHelper_MCP

* Update: `20260415`

## Function

IDA Plugin, exposing comprehensive IDA capabilities as [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) Server, enabling AI assistants (Claude, Cursor, etc.) to directly interact with IDA Pro for reverse engineering tasks.

Features:

- **Auto Port**: Automatically finds available port (8080-8099), with persistent port mapping per binary
- **Thread Safe**: All IDA API calls are safely executed on the main thread via `execute_sync`
- **Full Toolset**: 17 MCP tools covering decompilation, assembly, xrefs, renaming, commenting, type setting, struct definition, memory reading, exports, segments, and **batch operations**
- **Batch Operations**: Query multiple functions in one call (`get_ida_asm_code_batch`, `get_ida_pseudo_code_batch`, etc.) — dramatically reduces round-trips for bulk analysis
- **Flexible Address**: Support hex string, decimal, or symbol name for all address parameters
- **Menu Control**: (Re)Start/Stop MCP Server from IDA menu (`Edit` -> `MCP Server`) or hotkeys
- **Hot Reload**: (Re)Start auto-reloads plugin code from disk — no need to restart IDA after code changes
- **Logging**: Dual output to IDA Output window and log files with auto-cleanup

## Git Repo

https://github.com/crifan/idaAiHelper_MCP

https://github.com/crifan/idaAiHelper_MCP.git

## Prerequisites

Install the `mcp` Python package in your IDA Python environment:

```bash
pip install mcp
```

> Note: Make sure you install it into the Python environment that IDA Pro uses (e.g., IDA's bundled Python or your configured Python).

## Usage

### 1. Install Plugin

Copy `idaAiHelper_MCP.py` to your IDA plugins directory:

- **macOS**: `~/.idapro/plugins/` or `<IDA_install_dir>/plugins/`
- **Windows**: `%APPDATA%\Hex-Rays\IDA Pro\plugins\` or `<IDA_install_dir>\plugins\`
- **Linux**: `~/.idapro/plugins/` or `<IDA_install_dir>/plugins/`

### 2. (Re)Start MCP Server

After opening a binary in IDA Pro, use either:

- **Menu**: `Edit` -> `MCP Server` -> `(Re)Start`
- **Hotkey**: `Ctrl+Alt+S`

> **Hot Reload**: If the server is already running, clicking `(Re)Start` will stop it, reload the plugin code from disk, and start a fresh server — no need to restart IDA.

IDA Output window will show:

```
=================================================================
[idaAiHelper] >>> STARTED MCP Server : IDA_MCP_yourBinaryName
[idaAiHelper] >>> Listening on URL : http://127.0.0.1:8080/yourBinaryName/sse
=================================================================
```

### 3. Connect AI Client

Configure your AI client (Claude Desktop, Cursor, etc.) to connect to the MCP Server URL shown in the output.

Example MCP client config (for multiple IDA instances):

```json
{
  "mcpServers": {
    "ida_PerimeterX_SDK": {
      "url": "http://127.0.0.1:8080/PerimeterX_SDK/sse"
    },
    "ida_libmtguard_so": {
      "url": "http://127.0.0.1:8081/libmtguard_so/sse"
    }
  }
}
```

> The URL path contains the binary name (with special characters replaced by `_`). Check the IDA output window for the exact URL after starting the server.

### 4. Stop MCP Server

- **Menu**: `Edit` -> `MCP Server` -> `Stop`
- **Hotkey**: `Ctrl+Alt+T`

## MCP Tools

| Tool | Description |
|------|-------------|
| `get_ida_pseudo_code(ea)` | Get decompiled pseudocode (Hex-Rays) at address |
| `get_ida_asm_code(ea)` | Get assembly code of function at address |
| `get_ida_xrefs_to(ea)` | Get cross references TO the address |
| `get_ida_xrefs_from(ea)` | Get cross references FROM the function at address |
| `get_ida_pseudo_code_batch(ea_list)` | Batch decompile multiple functions in one call |
| `get_ida_asm_code_batch(ea_list)` | Batch get assembly for multiple functions in one call |
| `get_ida_xrefs_to_batch(ea_list)` | Batch get xrefs TO multiple addresses in one call |
| `get_ida_xrefs_from_batch(ea_list)` | Batch get xrefs FROM multiple addresses in one call |
| `read_ida_string(ea, maxLength)` | Read string at address |
| `read_ida_raw_bytes(ea, size)` | Read raw bytes at address |
| `read_ida_pointer(ea)` | Read pointer value at address |
| `get_ida_exports()` | Get all exports of the binary |
| `get_ida_segments()` | Get all segments info |
| `rename_ida_symbol(ea, newName)` | Rename symbol at address |
| `set_ida_comment(ea, comment, commentType)` | Set comment at address. commentType: "function" or "asm" |
| `set_ida_function_type(ea, typeSignature)` | Set function type signature |
| `add_ida_c_struct(cStructCode)` | Add C struct definition to IDA |

### Address Format

All `ea` (address) parameters support flexible input:
- **Hex string**: `"0x75adc"`, `"0x11C110"`
- **Decimal string**: `"481500"`
- **Symbol name**: `"sub_11C110"`, `"inflateDecompress_46500"`, `"main"`

### Batch Tools

Batch tools accept a comma-separated `ea_list` string and return all results in one call, dramatically reducing round-trips for bulk analysis:

```
ea_list = "sub_39B18,sub_39B5C,0x3A21C,sub_3AF20"
```

Output format:
```
=== sub_39B18 (0x39B18) ===
0x39B18: MOV X0, X1
...

=== sub_39B5C (0x39B5C) ===
0x39B5C: STP X29, X30, [SP,#-0x10]!
...
```

Individual address failures are reported inline without affecting other results.

### Persistent Port Mapping

Port assignments are saved to `~/.idaAiHelper_config.json` so each binary always gets the same port across restarts. This means you don't need to reconfigure your MCP client every time you restart IDA.

Example config file:
```json
{
  "portMapping": {
    "PerimeterX_SDK": 8080,
    "libmtguard_so": 8081
  }
}
```

### Logging

Log files are saved to `logs/` subdirectory (same location as the plugin script) with format:
```
idaAiHelper_MCP_{binaryName}_{YYYYMMDD_HHMMSS}.log
```

- **IDA Output**: Shows tool calls in real-time with `[idaAiHelper]` prefix
- **Log files**: Detailed timestamps for debugging and audit trail
- **Auto-cleanup**: Only keeps the latest 20 log files

Example log output:
```
[2026-03-04 15:30:00][INFO] Tool called: rename_ida_symbol(ea=0x74C7C, newName='addMxxxParamToJson_74C7C')
[2026-03-04 15:30:00][INFO] Tool result: Success
```
