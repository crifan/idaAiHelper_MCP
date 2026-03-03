# Function: IDA script plugin, exposing comprehensive IDA capabilities as MCP Server
# Author: Crifan Li
# Update: 20260303
# Feature: Auto-port, Thread-safe, Full Toolset, IDA Action Menu for Start/Stop Control

import sys
import sys

import sys
import sys
import io

import sys
import io

# =========================================================================
# IDAPython sys.stdout/stderr/stdin buffer 终极补丁 v4
# 包含 try-except，防止只读属性导致插件加载崩溃
# =========================================================================
class IDAPythonBufferPatch(io.BufferedIOBase):
    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        if isinstance(data, bytes):
            self.stream.write(data.decode('utf-8', 'replace'))
        else:
            self.stream.write(str(data))
        return len(data)

    def flush(self):
        if hasattr(self.stream, 'flush'):
            self.stream.flush()

    def close(self): pass 
    @property
    def closed(self): return False
    def readable(self): return False
    def writable(self): return True
    def seekable(self): return False
    def isatty(self): return False

# 替换 stdout
try:
    if hasattr(sys, "stdout"):
        sys.stdout.buffer = IDAPythonBufferPatch(sys.stdout)
except AttributeError:
    pass

# 替换 stderr
try:
    if hasattr(sys, "stderr"):
        sys.stderr.buffer = IDAPythonBufferPatch(sys.stderr)
except AttributeError:
    pass

# 替换 stdin
class DummyStdinBuffer(io.BufferedIOBase):
    def read(self, size=-1): return b""
    def readline(self): return b""
    def readable(self): return True
    def writable(self): return False
    def seekable(self): return False
    def isatty(self): return False
    def close(self): pass
    @property
    def closed(self): return False

try:
    if hasattr(sys, "stdin"):
        sys.stdin.buffer = DummyStdinBuffer()
except AttributeError:
    # 如果 sys.stdin.buffer 是只读的，直接忽略，SSE 模式通常不需要读取标准输入
    pass
# =========================================================================

import os
import re
import socket
import threading
import asyncio
import idc
import idaapi
import ida_kernwin
import ida_hexrays
import ida_nalt
import idautils
import ida_bytes
import ida_typeinf
import ida_name

from mcp.server.fastmcp import FastMCP

# ==============================================================================
# Util Classes
# ==============================================================================

CONFIG_FILE_PATH = os.path.expanduser("~/.idaAiHelper_config.json")

class ConfigUtil:
  @staticmethod
  def loadConfig():
    """Load config from ~/.idaAiHelper_config.json"""
    if os.path.exists(CONFIG_FILE_PATH):
      try:
        import json
        with open(CONFIG_FILE_PATH, 'r') as f:
          return json.load(f)
      except Exception as e:
        print("[idaAiHelper] Warning: Failed to load config: %s" % e)
    return {"portMapping": {}}

  @staticmethod
  def saveConfig(configDict):
    """Save config to ~/.idaAiHelper_config.json"""
    try:
      import json
      with open(CONFIG_FILE_PATH, 'w') as f:
        json.dump(configDict, f, indent=2)
    except Exception as e:
      print("[idaAiHelper] Warning: Failed to save config: %s" % e)

  @staticmethod
  def getPortForBinary(safeNameStr):
    """Get saved port for binary, or None if not found"""
    configDict = ConfigUtil.loadConfig()
    return configDict.get("portMapping", {}).get(safeNameStr)

  @staticmethod
  def savePortForBinary(safeNameStr, portInt):
    """Save port mapping for binary"""
    configDict = ConfigUtil.loadConfig()
    if "portMapping" not in configDict:
      configDict["portMapping"] = {}
    configDict["portMapping"][safeNameStr] = portInt
    ConfigUtil.saveConfig(configDict)

class CommonUtil:
  @staticmethod
  def getSafeName(rawNameStr):
    """Convert raw string to safe string for MCP server name"""
    return re.sub(r'[^a-zA-Z0-9]', '_', rawNameStr)

class NetworkUtil:
  @staticmethod
  def isPortAvailable(portInt):
    """Check if a specific port is available"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sObj:
      resultInt = sObj.connect_ex(('127.0.0.1', portInt))
      return resultInt != 0

  @staticmethod
  def findAvailablePort(startPortInt=8080, maxPortInt=8099):
    """Find an available port"""
    for portInt in range(startPortInt, maxPortInt + 1):
      if NetworkUtil.isPortAvailable(portInt):
        return portInt
    return None

  @staticmethod
  def getPortForBinary(safeNameStr, startPortInt=8080, maxPortInt=8099):
    """Get persistent port for binary: use saved port if available, otherwise allocate new one"""
    savedPortInt = ConfigUtil.getPortForBinary(safeNameStr)
    if savedPortInt is not None:
      if NetworkUtil.isPortAvailable(savedPortInt):
        return savedPortInt
      else:
        print("[idaAiHelper] Warning: Saved port %d for '%s' is occupied, finding new port..." % (savedPortInt, safeNameStr))
    # Find new available port and save it
    newPortInt = NetworkUtil.findAvailablePort(startPortInt, maxPortInt)
    if newPortInt:
      ConfigUtil.savePortForBinary(safeNameStr, newPortInt)
    return newPortInt

class IDAThreadUtil:
  @staticmethod
  def executeSync(funcObj, *args, **kwargs):
    """Safely execute IDA API calls on the main thread."""
    resultList = [None]
    exceptionList = [None]

    def wrapper():
      try:
        resultList[0] = funcObj(*args, **kwargs)
      except Exception as e:
        exceptionList[0] = e
      return 1

    idaapi.execute_sync(wrapper, idaapi.MFF_WRITE)
    if exceptionList[0]:
      print("[idaAiHelper] ExecuteSync Exception: %s" % exceptionList[0])
      return "Error: %s" % exceptionList[0]
    return resultList[0]

class IDAUtil:
  @staticmethod
  def getInputName():
    """Get current loaded binary file name in IDA"""
    fileNameStr = ida_nalt.get_root_filename()
    return fileNameStr if fileNameStr else "UnknownBinary"

  @staticmethod
  def parseAddress(addrInput):
    """Parse address from int, hex string '0x...', decimal string, or symbol name.
    Returns (ea: int, error: str or None). If error is not None, ea is invalid.
    """
    if isinstance(addrInput, int):
      return addrInput, None
    if not isinstance(addrInput, str):
      return 0, "Invalid address type: %s" % type(addrInput).__name__
    addrStr = addrInput.strip()
    # Try hex string "0x..."
    if addrStr.lower().startswith("0x"):
      try:
        return int(addrStr, 16), None
      except ValueError:
        return 0, "Invalid hex address: %s" % addrStr
    # Try pure decimal string
    if addrStr.isdigit():
      return int(addrStr), None
    # Try symbol name lookup
    ea = idc.get_name_ea_simple(addrStr)
    if ea != idc.BADADDR:
      return ea, None
    return 0, "Symbol not found: %s" % addrStr

  # ------------------ IDA API Wrappers (Internal) ------------------
  @staticmethod
  def _getPseudoCode(ea):
    if not ida_hexrays.init_hexrays_plugin(): return "Error: Hex-Rays not loaded."
    funcObj = idaapi.get_func(ea)
    if not funcObj: return "Error: No function at 0x%X" % ea
    try:
      cfuncObj = ida_hexrays.decompile(funcObj.start_ea)
      return str(cfuncObj) if cfuncObj else "Error: Decompile failed."
    except Exception as e:
      return "Exception: %s" % e

  @staticmethod
  def _renameSymbol(ea, newNameStr):
    isSuccess = idc.set_name(ea, newNameStr, idc.SN_NOWARN)
    idaapi.refresh_idaview_anyway()
    return isSuccess

  @staticmethod
  def _setComment(ea, commentStr, isFunctionBool=False):
    if isFunctionBool:
      funcObj = idaapi.get_func(ea)
      isSuccess = idc.set_func_cmt(funcObj.start_ea, commentStr, 1) if funcObj else False
    else:
      isSuccess = idc.set_cmt(ea, commentStr, 0) 
    idaapi.refresh_idaview_anyway()
    return isSuccess

  @staticmethod
  def _getAssemblyCode(ea):
    funcObj = idaapi.get_func(ea)
    asmCodeList = []
    if funcObj:
      for headEa in idautils.FuncItems(funcObj.start_ea):
        asmCodeList.append(f"0x{headEa:X}: {idc.generate_disasm_line(headEa, 0)}")
    else:
      currEa = ea
      for _ in range(5): 
        asmLineStr = idc.generate_disasm_line(currEa, 0)
        if not asmLineStr: break
        asmCodeList.append(f"0x{currEa:X}: {asmLineStr}")
        currEa += ida_bytes.get_item_size(currEa)
    return "\n".join(asmCodeList)

  @staticmethod
  def _getXrefsTo(ea):
    xrefsList = [f"Called from: 0x{x.frm:X} ({idc.get_func_name(x.frm) or idc.get_name(x.frm, ida_name.GN_VISIBLE)})" for x in idautils.XrefsTo(ea, 0)]
    return "\n".join(xrefsList) if xrefsList else "No cross references TO this address."

  @staticmethod
  def _getXrefsFrom(ea):
    xrefsList = []
    funcObj = idaapi.get_func(ea)
    startEa, endEa = (funcObj.start_ea, funcObj.end_ea) if funcObj else (ea, ea + 1)
    for headEa in idautils.Heads(startEa, endEa):
      for x in idautils.XrefsFrom(headEa, 0):
        targetNameStr = idc.get_name(x.to, ida_name.GN_VISIBLE)
        if targetNameStr: xrefsList.append(f"0x{headEa:X} refs: 0x{x.to:X} ({targetNameStr})")
    return "\n".join(xrefsList) if xrefsList else "No outgoing references found."

  @staticmethod
  def _setFunctionType(ea, typeStr):
    if not typeStr.strip().endswith(";"): typeStr += ";"
    isSuccess = ida_typeinf.apply_cdecl(ida_typeinf.get_idati(), ea, typeStr)
    idaapi.refresh_idaview_anyway()
    return isSuccess

  @staticmethod
  def _addCStruct(cStructCodeStr):
    errCountInt = ida_typeinf.parse_decls(ida_typeinf.get_idati(), cStructCodeStr, None, ida_typeinf.PT_SIL)
    idaapi.refresh_idaview_anyway()
    return errCountInt == 0

  @staticmethod
  def _getStringAtEa(ea, maxLenInt):
    resByteList = bytearray()
    currEa = ea
    while len(resByteList) < maxLenInt and ida_bytes.is_loaded(currEa):
      bInt = ida_bytes.get_byte(currEa)
      if bInt == 0: break
      resByteList.append(bInt)
      currEa += 1
    return resByteList.decode('utf-8', errors='ignore') if resByteList else "No valid string found."

  @staticmethod
  def _getRawBytes(ea, sizeInt):
    return " ".join([f"{b:02X}" for b in ida_bytes.get_bytes(ea, sizeInt)]) if ida_bytes.is_loaded(ea) else "Error: Memory not loaded."

  @staticmethod
  def _readPointer(ea):
    if not ida_bytes.is_loaded(ea): return "Error: Memory not loaded."
    ptrInt = ida_bytes.get_qword(ea) if idaapi.get_inf_structure().is_64bit() else ida_bytes.get_dword(ea)
    return "Pointer at 0x%X -> 0x%X" % (ea, ptrInt)

  @staticmethod
  def _getExports():
    exportList = [f"0x{ea:X} : {name}" for i, o, ea, name in idautils.Entries() if name]
    return "\n".join(exportList) if exportList else "No exports found."

  @staticmethod
  def _getSegmentsInfo():
    segList = [f"Segment: {idc.get_segm_name(s):10} | Start: 0x{idc.get_segm_start(s):X} | End: 0x{idc.get_segm_end(s):X}" for s in idautils.Segments()]
    return "\n".join(segList) if segList else "No segments info available."

# ==============================================================================
# MCP Server Wrapper
# ==============================================================================

class IDAMCPServer:
  def __init__(self):
    rawFileNameStr = IDAUtil.getInputName()
    self.safeFileNameStr = CommonUtil.getSafeName(rawFileNameStr)
    self.serverNameStr = "IDA_MCP_%s" % self.safeFileNameStr
    self.serverPortInt = None
    self.mountPathStr = "/%s" % self.safeFileNameStr
    self.mcpObj = FastMCP(
      self.serverNameStr,
      sse_path="%s/sse" % self.mountPathStr,
      message_path="%s/messages/" % self.mountPathStr,
    )
    self.serverThreadObj = None
    self.loopObj = None
    self.isRunningBool = False
    self._registerTools()

  def _registerTools(self):
    def _parseEa(eaInput):
      ea, err = IDAThreadUtil.executeSync(IDAUtil.parseAddress, eaInput)
      return ea, err

    @self.mcpObj.tool()
    def get_ida_pseudo_code(ea: str) -> str:
      """Get decompiled pseudo code. ea: hex string '0x...', decimal, or symbol name."""
      addr, err = _parseEa(ea)
      if err: return "Error: %s" % err
      print("[idaAiHelper] Tool called: get_ida_pseudo_code(0x%X)" % addr)
      r = IDAThreadUtil.executeSync(IDAUtil._getPseudoCode, addr)
      print("[idaAiHelper] Tool result: %s" % (r[:200] if r else repr(r)))
      return r

    @self.mcpObj.tool()
    def get_ida_asm_code(ea: str) -> str:
      """Get assembly code. ea: hex string '0x...', decimal, or symbol name."""
      addr, err = _parseEa(ea)
      if err: return "Error: %s" % err
      print("[idaAiHelper] Tool called: get_ida_asm_code(0x%X)" % addr)
      r = IDAThreadUtil.executeSync(IDAUtil._getAssemblyCode, addr)
      print("[idaAiHelper] Tool result: %s" % (r[:200] if r else repr(r)))
      return r

    @self.mcpObj.tool()
    def get_ida_xrefs_to(ea: str) -> str:
      """Get cross references TO address. ea: hex string '0x...', decimal, or symbol name."""
      addr, err = _parseEa(ea)
      if err: return "Error: %s" % err
      print("[idaAiHelper] Tool called: get_ida_xrefs_to(0x%X)" % addr)
      r = IDAThreadUtil.executeSync(IDAUtil._getXrefsTo, addr)
      print("[idaAiHelper] Tool result: %s" % (r[:200] if r else repr(r)))
      return r

    @self.mcpObj.tool()
    def get_ida_xrefs_from(ea: str) -> str:
      """Get cross references FROM address. ea: hex string '0x...', decimal, or symbol name."""
      addr, err = _parseEa(ea)
      if err: return "Error: %s" % err
      print("[idaAiHelper] Tool called: get_ida_xrefs_from(0x%X)" % addr)
      r = IDAThreadUtil.executeSync(IDAUtil._getXrefsFrom, addr)
      print("[idaAiHelper] Tool result: %s" % (r[:200] if r else repr(r)))
      return r

    @self.mcpObj.tool()
    def read_ida_string(ea: str, maxLength: int = 256) -> str:
      """Read string at address. ea: hex string '0x...', decimal, or symbol name."""
      addr, err = _parseEa(ea)
      if err: return "Error: %s" % err
      return IDAThreadUtil.executeSync(IDAUtil._getStringAtEa, addr, maxLength)

    @self.mcpObj.tool()
    def read_ida_raw_bytes(ea: str, size: int) -> str:
      """Read raw bytes. ea: hex string '0x...', decimal, or symbol name."""
      addr, err = _parseEa(ea)
      if err: return "Error: %s" % err
      return IDAThreadUtil.executeSync(IDAUtil._getRawBytes, addr, size)

    @self.mcpObj.tool()
    def read_ida_pointer(ea: str) -> str:
      """Read pointer at address. ea: hex string '0x...', decimal, or symbol name."""
      addr, err = _parseEa(ea)
      if err: return "Error: %s" % err
      return IDAThreadUtil.executeSync(IDAUtil._readPointer, addr)

    @self.mcpObj.tool()
    def get_ida_exports() -> str:
      """Get all exports."""
      print("[idaAiHelper] Tool called: get_ida_exports()")
      r = IDAThreadUtil.executeSync(IDAUtil._getExports)
      print("[idaAiHelper] Tool result: %s" % (r[:200] if r else repr(r)))
      return r

    @self.mcpObj.tool()
    def get_ida_segments() -> str:
      """Get all segments info."""
      print("[idaAiHelper] Tool called: get_ida_segments()")
      r = IDAThreadUtil.executeSync(IDAUtil._getSegmentsInfo)
      print("[idaAiHelper] Tool result: %s" % (r[:200] if r else repr(r)))
      return r

    @self.mcpObj.tool()
    def rename_ida_symbol(ea: str, newName: str) -> str:
      """Rename symbol. ea: hex string '0x...', decimal, or symbol name."""
      addr, err = _parseEa(ea)
      if err: return "Error: %s" % err
      return "Success" if IDAThreadUtil.executeSync(IDAUtil._renameSymbol, addr, newName) else "Failed"

    @self.mcpObj.tool()
    def set_ida_comment(ea: str, comment: str, isFunction: bool) -> str:
      """Set comment. ea: hex string '0x...', decimal, or symbol name."""
      addr, err = _parseEa(ea)
      if err: return "Error: %s" % err
      return "Success" if IDAThreadUtil.executeSync(IDAUtil._setComment, addr, comment, isFunction) else "Failed"

    @self.mcpObj.tool()
    def set_ida_function_type(ea: str, typeSignature: str) -> str:
      """Set function type signature. ea: hex string '0x...', decimal, or symbol name."""
      addr, err = _parseEa(ea)
      if err: return "Error: %s" % err
      return "Success" if IDAThreadUtil.executeSync(IDAUtil._setFunctionType, addr, typeSignature) else "Failed"

    @self.mcpObj.tool()
    def add_ida_c_struct(cStructCode: str) -> str:
      """Add C struct definition to IDA types."""
      return "Success" if IDAThreadUtil.executeSync(IDAUtil._addCStruct, cStructCode) else "Failed"

  def start(self):
    if self.isRunningBool:
      print("[idaAiHelper] Warning: MCP Server '%s' is already running on port %s." % (self.serverNameStr, self.serverPortInt))
      return
      
    self.serverPortInt = NetworkUtil.getPortForBinary(self.safeFileNameStr, 8080, 8099)
    if not self.serverPortInt:
      print("[idaAiHelper] Error: No available ports for '%s'." % self.serverNameStr)
      return

    def run_mcp_loop():
      self.loopObj = asyncio.new_event_loop()
      asyncio.set_event_loop(self.loopObj)
      self.mcpObj.settings.port = self.serverPortInt
      try:
        self.mcpObj.run(transport="sse")
      except Exception as e:
        print("[idaAiHelper] Server '%s' stopped unexpectedly: %s" % (self.serverNameStr, e))

    self.serverThreadObj = threading.Thread(target=run_mcp_loop)
    self.serverThreadObj.daemon = True
    self.serverThreadObj.start()
    self.isRunningBool = True
    
    print("\n" + "="*65)
    print("[idaAiHelper] >>> STARTED MCP Server : %s" % self.serverNameStr)
    print("[idaAiHelper] >>> Listening on URL : http://localhost:%d%s/sse" % (self.serverPortInt, self.mountPathStr))
    print("="*65 + "\n")

  def stop(self):
    if not self.isRunningBool or not self.loopObj:
      return
      
    print("\n" + "="*65)
    print("[idaAiHelper] >>> STOPPED MCP Server : %s" % self.serverNameStr)
    print("[idaAiHelper] >>> Released Port    : %s" % self.serverPortInt)
    print("="*65 + "\n")
    
    # Safely shut down the asyncio event loop to release the port
    self.loopObj.call_soon_threadsafe(self.loopObj.stop)
    self.isRunningBool = False
    self.serverPortInt = None

# ==============================================================================
# IDA Plugin & Action Registration
# ==============================================================================

class ActionStartMCP(idaapi.action_handler_t):
  def __init__(self, pluginObj):
    idaapi.action_handler_t.__init__(self)
    self.pluginObj = pluginObj

  def activate(self, ctx):
    self.pluginObj.actionStart()
    return 1

  def update(self, ctx):
    return idaapi.AST_ENABLE_ALWAYS

class ActionStopMCP(idaapi.action_handler_t):
  def __init__(self, pluginObj):
    idaapi.action_handler_t.__init__(self)
    self.pluginObj = pluginObj

  def activate(self, ctx):
    self.pluginObj.actionStop()
    return 1

  def update(self, ctx):
    return idaapi.AST_ENABLE_ALWAYS

class IDAMCPPlugin(idaapi.plugin_t):
  flags = idaapi.PLUGIN_KEEP
  comment = "IDA MCP Server Plugin"
  help = "Exposes IDA API via Model Context Protocol"
  wanted_name = "IDA MCP Server Core"
  wanted_hotkey = "" 

  def init(self):
    self.mcpServerObj = None
    self.actionStartNameStr = "mcp_server:start"
    self.actionStopNameStr = "mcp_server:stop"
    
    targetNameStr = IDAUtil.getInputName()
    safeTargetNameStr = CommonUtil.getSafeName(targetNameStr)
    
    # 预先存下预期的 Server Name，方便在服务未启动时打印
    self.expectedServerNameStr = "IDA_MCP_%s" % safeTargetNameStr

    # 1. 注册 Start 动作
    idaapi.register_action(idaapi.action_desc_t(
      self.actionStartNameStr,
      f"Start MCP Server: {self.expectedServerNameStr}",
      ActionStartMCP(self),
      "Ctrl+Alt+S",
      "Start the AI MCP Server",
      199 # Icon ID
    ))

    # 2. 注册 Stop 动作
    idaapi.register_action(idaapi.action_desc_t(
      self.actionStopNameStr,
      f"Stop MCP Server: {self.expectedServerNameStr}",
      ActionStopMCP(self),
      "Ctrl+Alt+T",
      "Stop the AI MCP Server",
      200 # Icon ID
    ))

    # 3. 挂载到顶部菜单栏 Edit -> MCP Server
    idaapi.attach_action_to_menu("Edit/MCP Server/Start", self.actionStartNameStr, idaapi.SETMENU_APP)
    idaapi.attach_action_to_menu("Edit/MCP Server/Stop", self.actionStopNameStr, idaapi.SETMENU_APP)

    print(f"[idaAiHelper] Plugin loaded for '{self.expectedServerNameStr}'. Check 'Edit -> MCP Server' menu.")
    return idaapi.PLUGIN_KEEP

  def actionStart(self):
    # 校验是否已启动，并带上详细名称和端口提示
    if self.mcpServerObj and self.mcpServerObj.isRunningBool:
      print("[idaAiHelper] Action Ignore: Server '%s' is ALREADY running on port %s!" % (self.mcpServerObj.serverNameStr, self.mcpServerObj.serverPortInt))
      return
      
    self.mcpServerObj = IDAMCPServer()
    self.mcpServerObj.start()

  def actionStop(self):
    # 校验是否正在运行，带上详细提示
    if self.mcpServerObj and self.mcpServerObj.isRunningBool:
      self.mcpServerObj.stop()
    else:
      print("[idaAiHelper] Action Ignore: Server '%s' is NOT running right now." % self.expectedServerNameStr)

  def run(self, arg):
    pass

  def term(self):
    if self.mcpServerObj:
      self.mcpServerObj.stop()

def PLUGIN_ENTRY():
  return IDAMCPPlugin()