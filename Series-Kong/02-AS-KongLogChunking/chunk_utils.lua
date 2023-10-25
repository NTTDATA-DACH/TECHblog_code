--[[
  
Disclaimer:
NTT DATA Deutschland SE gives no assurances regarding the suitability and usability of the code snippet provided here. The code snippet is provided without warranty of any kind and may be used in any identical or edited form. Accordingly, NTT DATA Deutschland SE hereby excludes all warranties and guarantees with respect to the code snippet, including all explicit, implied or statutory warranties and guarantees of merchantability, fitness for purpose, title and non-infringement. In no event shall NTT DATA Deutschland SE be liable for any direct, indirect and/or consequential damages and/or any damages whatsoever.

Haftungsausschluss:
Die NTT DATA Deutschland SE gibt keine Zusicherungen hinsichtlich der Eignung und Verwendbarkeit des hier zur Verfügung gestellten Codeschnipsels. Der Codeschnipsel wird ohne Gewährleistung jeglicher Art bereitgestellt und kann beliebig identisch bzw. bearbeitet genutzt werden. Entsprechend schließt die NTT DATA Deutschland SE hiermit sämtliche Gewährleistungen und Garantien in Bezug auf den Codeschnipsel aus, einschließlich sämtlicher ausdrücklicher, konkludenter oder gesetzlicher Gewährleistungen und Garantien in Bezug auf Handelsüblichkeit, Eignung und Eigentum und Verletzung von Rechten Dritter. In keinem Fall ist die NTT DATA Deutschland SE für direkte, indirekte Schäden und /oder Folgeschäden und / oder Schäden welcher Art auch immer haftbar zu machen.

-------

  name = "chunk_utils"
  author = Alexander Suchier, NTT DATA Deutschland SE
  description = "chunk utilities"

  syntax: [<chunk id>, <chunk index>, <total chunks>, <chunk size>]

  syntax example: 
    log prefix [18871860ab0,1,2,3896] log message
    log prefix [18871860ab0,2,2,185] remaining log message
--]]

local utils = require 'kong.tools.utils'
local uuid = utils.uuid

-- Penlight Lua string library, also used Kong internally 
local stringx = require "pl.stringx"

local chunker = {}

-- read Kong knowledge base article number 000001781 for details
-- logging buffer is for prefixing and tailing string buffering
-- tailing information may be cut off, but can be accepted (info likely on last chunk, anyway redundant)
-- increase the buffer, if tailing information is lost which you want to keep
local OPENRESTY_LOGGING_CHAR_MAX = 4096
local LOGGING_CHAR_BUFFER = 396

-- do chunking regardless of the text size?
-- often it es not necessary to split the text, then a normal output occurs (default:false)
local ALWAYS_ENFORCED_CHUNKING = false

-- enable "real" caller information output when outputting via this module
-- the real caller information can be determined, which would otherwise be lost (default:true)
local ENABLE_CALLER_INFORMATION = true

-- EOC = End Of Chunk, facilitates direct visibility when a chunk has ended
-- if not wanted, then set to empty string (default:EOC)
local EOC_MARKING = 'EOC'


--[[
  split text into chunks
  @param `text`      Text which has to be splitted
  @param `chunkSize` Chunk size 
  @return Table with chunks
--]]
local function _splitToChunks(text, chunkSize)
  local strTab = {}

  for i=1, #text, chunkSize do
    strTab[#strTab+1] = text:sub(i,i+chunkSize-1)
  end

  return strTab
end


--[[
  split text into chunks with numbered prefix
  @param `text`      Text which has to be splitted
  @param `chunkSize` Chunk size including chunk prefix
  @return Table with chunks
--]]
local function _splitToNumberedChunks(text, chunkSize)
  local chunksTab = {}   

  -- just timestamp is not enough for uniqueness at concurrence logging (even ms), add uuid hex parts
  -- (only uuid is far too long and would take up too much space from the actual logging text)
  local timestampMS = os.time() * 1000 
  local chunkId = uuid():sub(1,4) .. string.format('%x', timestampMS)

  local chunkStrTab = _splitToChunks(text,chunkSize)

  for chunkIndex,chunkText in ipairs(chunkStrTab) do
    -- chunkId: unique chunk number
    -- chunkIndex: indexed chunk numbering
    -- #chunkStrTab: number of total chunks (table size)
    -- #chunkText: size of the actual chunk (string size)
    -- chunkText: chunk text
    chunksTab[chunkIndex] = stringx.join('',{'[',chunkId,',',chunkIndex,',',#chunkStrTab,',',#chunkText,'] ',chunkText,EOC_MARKING})
  end

  return chunksTab
end


--[[
  log text with numbered chunks and given chunk size
  @param `callerStr` Caller information string
  @param `text`      Text which has to be splitted
  @param `chunkSize` Chunk size 
  @return Table with chunks
--]]
local function _logChunksSize(log, callerStr, text, chunkSize)
  local chunksTab = _splitToNumberedChunks(text,chunkSize)   

  for chunk,chunkText in ipairs(chunksTab) do
    log(callerStr,chunkText)
  end
end


--[[
  log text with chunks
  @param `log`       Function which logs the text
  @param `callerStr` Caller information string  
  @param `...`       Arguments to be logged
  @return Table with composed and stringified log arguments
--]]
local function _logChunks(log, caller, ...)
  local args = {...}
  local text = ''

  -- string conversion for length check  
  for i = 1, #args do
    text = text .. tostring(args[i])
  end

  if (log and text) then
    local chunkSize = OPENRESTY_LOGGING_CHAR_MAX - LOGGING_CHAR_BUFFER
    local chunkNeeded = (#text > chunkSize) or ALWAYS_ENFORCED_CHUNKING

    local callerStr = ''

    if (ENABLE_CALLER_INFORMATION) then
      -- notice: empty lines are removed by Kong 
      -- (take a look at Kong Manager plugin site for affected module)
      callerStr = '[' .. caller['short_module'] .. '>' .. caller['currentline'] .. '] '
    end
  
    if (chunkNeeded) then
      _logChunksSize(log,callerStr,text,chunkSize)
    else
      log(callerStr,unpack(args))
    end

    -- possibly interesting to have the log assembled string which may be further needed
    return text
  end

  return nil
end


--[[
  get trace stack
  @return Table with trace stack, chunker stack information is filtered out
--]]
local function _getTraceStack()
  local stack = {}
  local stackLevel = 1
  local stackFilter = ''

  while true do
    -- S:selects fields source, short_src, waht and linedefined
    -- l: selects currentline
    local info = debug.getinfo(stackLevel,'Sl')

    if (not(info)) then 
      break 
    end	

    -- getinfo calling module = chunker (always first on stack)
    if (stackLevel==1) then
       -- '.': means any character
       -- '+': a quantifier that matches one or more occurrences of the preceding element
       -- 'anything (or nothing), followed by @, followed by anything'
       stackFilter = info.source:match('@(.+)')
    end
   
    -- filter on own module stack 
    if (string.match(info.source,stackFilter)==nil) then
      table.insert(stack,info)
    end 

    stackLevel = stackLevel + 1
  end

  return stack
end


--[[
  get short module name
  @param `module` Full module path string   
  @return Short module name
--]]
local function _getShortModuleName(module)
  local shortModuleName = ''

  if (module) then
    local moduleSplit = stringx.split(module,'/')

    if (moduleSplit) then
      shortModuleName = moduleSplit[#moduleSplit]
    end
  end

  return shortModuleName
end


--[[
  get plugin name
  @param `serverless` Serverless?    
  @param `module`     Full module path string   
  @return Plugin name
--]]
local function _getPluginName(serverless,module)
  local pluginName = ''

  if (module) then
    local moduleSplit = stringx.split(module,'/')

    if ((serverless) and (#moduleSplit>=2)) then
      pluginName = moduleSplit[2]
    else
      for key, value in ipairs(moduleSplit) do
        if ((value=='plugins') and (#moduleSplit>key)) then
          pluginName = moduleSplit[key+1]
        end
      end
    end
  end

  return pluginName
end


--[[
  get trace stack (some stack trace arithmetic)
  @return Table with trace stack
--]]
local function _getCaller()
  local caller = {}
  local stack = _getTraceStack()

  if (stack) then
    -- C-functions cannot be evaluated
    if ((#stack>=1) and (stack[1].what~='C')) then
      caller['what'] = stack[1].what
      caller['short_src'] = stack[1].short_src
      caller['currentline'] = stack[1].currentline

      -- Kong short name for serverless is [string "..."]
      if (stack[1].short_src=='[string "..."]') then
        caller['serverless'] = true
      
        -- take a look at the next stack
        if ((#stack>=2) and (stack[2].what~='C')) then
           caller['module'] = stack[2].source:match('@(.+)')
        end
      else
        caller['serverless'] = false
        caller['module'] = stack[1].source:match('@(.+)')
      end

      local shortModule = stringx.split(caller['module'],'/')
      
      caller['short_module'] = _getShortModuleName(caller['module'])
      caller['plugin'] = _getPluginName(caller['serverless'],caller['module'])
    end
  end

  return caller
end


--[[
  logChunks function publisher
--]]
function chunker.logChunks(log, ...)
  local args = {...}
  
  -- get the stack information early (avoid more chunker stack information)
  local caller = _getCaller(log)

  return _logChunks(log,caller,unpack(args))
end


return {
  chunker = chunker
}
