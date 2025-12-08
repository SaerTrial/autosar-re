import json
import re
import time
import datetime
import os

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.symbol import SourceType

from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet
from ghidra.program.model.block import IsolatedEntrySubModel
from ghidra.util import SystemUtilities


"""
exec(open("/home/audit/Documents/R_CGW_SWEET400/script/AUTOSAR_rename/AUTOSAR_renameProto.py").read())
"""

ID_ADDR     = 0
ID_MODULE   = 1
PREFIX      = "auto_"


def det_functionIsInList(functionList, functionName):
    result = False
    for funcAddr in functionList:
        func = getFunctionAt(toAddr(funcAddr))
        if (func is not None) and (func.getName() in functionName):
            result = True
    return result


def det_functionIsRenamed(functionAddr):
    result = False
    func = getFunctionAt(toAddr(functionAddr))
    if (func is not None) and (not func.getName().startswith("FUN_")):
        result =  True
    return result


def det_functionExtractSubList(function, paramNumber):
    sublist = []
    for funcAddr in function:
        func = getFunctionAt(toAddr(funcAddr))
        if (func is not None) and (func.getParameterCount() == paramNumber) and (not det_functionIsRenamed(funcAddr)):
            sublist.append(funcAddr)
    return sublist


def det_setNameInfo(moduleId, serviceId , addrToComment, spec):
    listing     = currentProgram.getListing()
    codeUnit    = listing.getCodeUnitAt(addrToComment)
    func        = getFunctionContaining(addrToComment)

    if moduleId in spec:
        if serviceId in spec[moduleId]["services"]:
            detFunctionName     = spec[moduleId]["services"][serviceId]["name"]
            detFunctionParam    = int(spec[moduleId]["services"][serviceId]["param"])
            codeUnit.setComment(codeUnit.EOL_COMMENT,detFunctionName)
            callTraceList           = det_retreiveCallTrace(addrToComment)
            callTraceReducedList    = det_functionExtractSubList(callTraceList, detFunctionParam)
            if not det_functionIsInList(callTraceList, detFunctionName):
                if len(callTraceReducedList) == 1:
                    f1 = getFunctionAt(toAddr(callTraceReducedList[0]))
                    f1.setName(PREFIX + detFunctionName, SourceType.USER_DEFINED)
                    print("[Info][Rename] %d reduced to %d candidate(s) found "
                          "for %s # moduleId=%s, serviceId=%s" % (len(callTraceList),
                                                                  len(callTraceReducedList),
                                                                  addrToComment,
                                                                  moduleId,
                                                                  serviceId))
                elif len(callTraceList) == 1 and func.getName().startswith("FUN_"):
                    func.setName(PREFIX + detFunctionName + "?", SourceType.USER_DEFINED)
                    print("[Info][Rename][Proto] Only 1 candidate by prototype "
                          "not match for %s # moduleId=%s, serviceId=%s" % (addrToComment, moduleId, serviceId))
                else:
                    print("[Info][NOT][Rename] %d reduced to %d candidate(s) "
                          "found for %s # moduleId=%s, serviceId=%s" % (len(callTraceList),
                                                                        len(callTraceReducedList),
                                                                        addrToComment,
                                                                        moduleId,
                                                                        serviceId))
        else:
            codeUnit.setComment(codeUnit.EOL_COMMENT,spec[moduleId]["abbreviation"])
            print("[Warning] Unknown 'serviceId' "
                  "at %s # moduleId=%02x, serviceId=%02x" % (addrToComment, int(moduleId), int(serviceId)))
    else:
        print("[Warning] Unknown 'moduleId' "
              "at %s # moduleId=%02x, serviceId=%02x" % (addrToComment, int(moduleId), int(serviceId)))


def buildAST(func):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    ifc.setSimplificationStyle("normalize")
    res = ifc.decompileFunction(func, 60, monitor)
    high = res.getHighFunction()
    return high


def det_retreiveCallTrace(addrReference):
    functionList    = []
    bbVisited       = []
    bbToVisit       = []
    func = getFunctionContaining(addrReference)
    if func is None:
        return functionList
    functionList.append(func.getEntryPoint().toString())
    high = buildAST(func)
    opiter = high.getPcodeOps()
    while opiter.hasNext():
        node = opiter.next()
        if node.getMnemonic() == "CALL" and node.getParent().contains(addrReference):
            for i in range(node.getParent().getInSize()):
                bbToVisit.append(node.getParent().getIn(i))
                bbVisited.append(node.getParent().getIn(i).toString())
            while len(bbToVisit) != 0:
                pblock = bbToVisit.pop(0)
                for op in pblock.getIterator():
                    if op.getMnemonic() == "CALL":
                        if op.getInput(0).getAddress() not in functionList:
                            functionList.append(op.getInput(0).getAddress().toString())
                for i in range(pblock.getInSize()):
                    if pblock.getIn(i).toString() not in bbVisited:
                        bbVisited.append(pblock.getIn(i).toString())
                        bbToVisit.append(pblock.getIn(i))
    
    return functionList


def det_retreiveFunctionName(addrReference, detFunctionAddr, spec, constPropagation=False):
    func = getFunctionContaining(addrReference)
    found = False
    if func is not None:
        high = buildAST(func)
        opiter = high.getPcodeOps()
        while opiter.hasNext() and not found:
            node = opiter.next()
            if node.getMnemonic() == "CALL" \
                    and node.getParent().contains(addrReference) \
                    and node.getInput(0).getAddress() == toAddr(detFunctionAddr):
                param1 = node.getInput(1)
                param3 = node.getInput(3)
                found = True
                if param1 is not None and param3 is not None and param1.isConstant() and param3.isConstant():
                    p1 = param1.getOffset() 
                    p3 = param3.getOffset() 
                    det_setNameInfo(str(p1), str(p3), node.getInput(0).getPCAddress(), spec)
                elif constPropagation and param1 is not None and param3 is not None:
                    print("[Warning] Parsing error %s but trying to trace backwards" % node.getInput(0).getPCAddress().toString())
                    p1 = param1.getOffset() if param1.isConstant() else None 
                    p3 = param3.getOffset() if param3.isConstant() else None 

                    if not param1.isConstant():
                        p1 = getConstantValue(param1)
                        if p1 is None:
                            if not param1.getAddress().getAddressSpace().isMemorySpace():
                                constParam = tryGetInputParamIfConst(high, param1)
                                if constParam is not None: 
                                    # print("[Info] param {} is passed with a const {}".format(param1, constParam.getOffset()))
                                    p1 = constParam.getOffset()
                
                    if not param3.isConstant():
                        p3 = getConstantValue(param3)
                        if p3 is None:
                            if not param3.getAddress().getAddressSpace().isMemorySpace():
                                constParam = tryGetInputParamIfConst(high, param3)
                                if constParam is not None:
                                    # print("[Info] param {} is passed with a const {}".format(param3, constParam.getOffset()))
                                    p3 = constParam.getOffset()
                    if p1 is not None and p3 is not None:
                        # print("[Info] at{}, p1: {}, p3: {}".format(addrReference, p1, p3))
                        det_setNameInfo(str(p1), str(p3), node.getInput(0).getPCAddress(), spec)
                else:
                    print("[Error] Parsing error %s" % node.getInput(0).getPCAddress().toString())
            
    if not found:
        print("[Warning] Cross reference not found %s" % addrReference.toString())


def det_retreiveSubFunctionName(addrReference, detFunctionAddr, moduleId, spec):
    func = getFunctionContaining(addrReference)
    found = False
    if func is not None:
        high = buildAST(func)
        opiter = high.getPcodeOps()
        while opiter.hasNext() and not found:
            node = opiter.next()
            if node.getMnemonic() == "CALL" and node.getParent().contains(addrReference) and node.getInput(0).getAddress() ==  toAddr(detFunctionAddr):
                param1 = node.getInput(1)
                found = True
                if param1 != None and param1.isConstant():
                    p1 = parseInt(param1.toString())
                    det_setNameInfo(str(moduleId), str(p1), node.getInput(0).getPCAddress(), spec)
                else:
                    print("[Error] Parsing error %s " % node.getInput(0).getPCAddress().toString())
    if found:
        print("[Warning] Cross reference not found %s " % addrReference.toString())


def det_rename(jsonFile, detFuncList, detSubFuncList, undefinedEntries, createUndefinedFunc=False, constPropagation=False):
    if not os.path.isfile(jsonFile):
        print("[Info] Problem with jsonFile")
        return
    with open(jsonFile) as f:
        spec = json.load(f)
        for detFunctionAddr in detFuncList:
            references = getReferencesTo(toAddr(detFunctionAddr))
            for xref in references:
                func = getFunctionContaining(xref.getFromAddress())
                if func is None:
                    print("[Info] Function not defined {}, but try to rebuild".format(xref.getFromAddress()))
                    if createUndefinedFunc and searchUndefinedEntryByCallsite(xref, undefinedEntries):
                        if getFunctionContaining(xref.getFromAddress()):
                            det_retreiveFunctionName(xref.getFromAddress(), detFunctionAddr, spec, constPropagation)
                else:
                    det_retreiveFunctionName(xref.getFromAddress(), detFunctionAddr, spec, constPropagation)
        for subfunc in detSubFuncList :
            references = getReferencesTo(toAddr(subfunc[0]))
            for xref in references:
                func = getFunctionContaining(xref.getFromAddress())
                if func is None:
                    print("[Info] Function not defined %s " % xref.getFromAddress())
                else:
                    det_retreiveSubFunctionName(xref.getFromAddress(), subfunc[ID_ADDR], subfunc[ID_MODULE], spec)


def getDecompiledParamCount(highfunc):
    if highfunc is None:
        return 0
    proto = highfunc.getFunctionPrototype()
    return proto.getNumParams()


def tryGetInputParamIfConst(high, vn):
    proto = high.getFunctionPrototype()
    func = high.getFunction()
    numParams = proto.getNumParams()
    paramIndex = set()
    for i in range(numParams):
        pv = proto.getParam(i)
        storage = pv.getStorage() 
        for param_vn in storage.getVarnodes():
            if param_vn.getAddress() == vn.getAddress():
                paramIndex.add(i)
    if len(paramIndex) == 1:
        idx = paramIndex.pop()
    
        references = getReferencesTo(high.getFunction().getEntryPoint())
        if len(references) != 1:
            return None
        
        idxParam = retriveParameterByIdx(references[0].getFromAddress(), func.getEntryPoint(), idx)
        if idxParam is not None and idxParam.isConstant():
            return idxParam
    
    return None
		
			
def retriveParameterByIdx(referenceCallerAddr, calleeAddr, idx):
    func = getFunctionContaining(referenceCallerAddr)
    found = False
    if func is not None:
            high = buildAST(func)
            opiter = high.getPcodeOps()
            while opiter.hasNext() and not found:
                node = opiter.next()
                if node.getMnemonic() == "CALL" \
                    		and node.getParent().contains(referenceCallerAddr) \
                    		and node.getInput(0).getAddress() == calleeAddr:
                    param = node.getInput(idx+1)
                    return param
    return None


# check if a node is defined locally
def getConstantValue(node):
	if node is None:
		return None

	if node.isConstant():
		return node.getOffset()

	def_node = node.getDef()
	if def_node is None or node.isInput():
		return None

	if def_node.getOpcode() == def_node.COPY:
		return getConstantValue(def_node.getInput(0))
	elif def_node.getOpcode() == def_node.INT_ADD:
		a = getConstantValue(def_node.getInput(0))
		b = getConstantValue(def_node.getInput(1))
		if a is not None and b is not None:
			return a + b
	elif def_node.getOpcode() == def_node.INT_MULT:
		x = getConstantValue(def_node.getInput(0))
		y = getConstantValue(def_node.getInput(1))
		if x is not None and y is not None:
			return x * y
	elif def_node.getOpcode() == def_node.MULTIEQUAL:
		phiConst = set()
		for i in range(def_node.getNumInputs()):
			try:
				res = getConstantValue(def_node.getInput(i))
				phiConst.add(res)
			except RuntimeError:
				return None
		if len(phiConst) == 1:
			return phiConst.pop()

	return None


def getFuncByRefCount(searchRange=10):
    fm = currentProgram.getFunctionManager()
	# frequency dictionary: { callee addr : count }
    freq = {}
    funcs = fm.getFunctions(True)
    for func in funcs:
        funEntrypoint = func.getEntryPoint().getOffset()
        freq[funEntrypoint] = len(getReferencesTo(toAddr(funEntrypoint)))
    funcByFreq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    funcByFreq = funcByFreq[:searchRange]
    return funcByFreq


def searchErrorHandlerCandidate():
    candicates = [] # func with four params and a return value
    potentialCandidates = [] # func with four params but no return value
    funcByFreq = getFuncByRefCount(10)
    for calleeAddr, refCount in funcByFreq:
        print("[Info] Callee addr = 0x{:x}, Reference count = {}".format(calleeAddr, refCount))
        func = getFunctionAt(toAddr(calleeAddr))
        high = buildAST(func)
        if getDecompiledParamCount(high) != 4:
            continue
        opiter = high.getPcodeOps()
        HasReturnValue = False
        ReturnValue = set()
        while opiter.hasNext():
            node = opiter.next()
            # [0]=return address, [1]=return value (varnode for returned value)

            if node.getOpcode() != node.RETURN:
                        continue
            if node.getNumInputs() < 2:
                        continue
            HasReturnValue |= True

            def_node = node.getInput(1).getDef()

            if def_node is not None:
                try: 
                    ret = getConstantValue(def_node.getInput(0))
                    ReturnValue.add(ret)
                except RuntimeError:
                    print("[Error] Analysis runs out of scope")
                    exit(1)
        
        # check if Det_ReportError or Det_ReportRuntimeError (always return a value)
        if HasReturnValue and len(ReturnValue) != 0:
            candicates.append(func.getEntryPoint().getOffset())
        if not HasReturnValue:
            potentialCandidates.append(func.getEntryPoint().getOffset())

    for candidate in candicates:
        print("[Info] Candidate addr = 0x{:x}".format(candidate))

    if len(candicates) == 0:
        print("[WARNING] Not found candidate for Det_ReportError or Det_ReportRuntimeError. Research {} manually".format(potentialCandidates))
        exit(1)

    return candicates


"""helper
# after the following, set: [[00001000, 000010ff] ]
set.addRange(toAddr(0x1000), toAddr(0x10FF))
# after the following, set: [[00001000, 0000100f] [00001051, 000010ff] ]
set.delete(toAddr(0x1010), toAddr(0x1050))
"""
def findUndefinedCalls():
    set = AddressSet()
    listing = currentProgram.getListing()

    initer = listing.getInstructions(currentProgram.getMemory(), True)
    while initer.hasNext() and not monitor.isCancelled():
        instruct = initer.next()
        set.addRange(instruct.getMinAddress(), instruct.getMaxAddress())

    iter = listing.getFunctions(True)
    while iter.hasNext() and not monitor.isCancelled():
        f = iter.next()
        set.delete(f.getBody())

    if set.getNumAddressRanges() == 0:
        print("NO RESULTS - all instructions are contained inside functions")
        exit(0)

    # go through address set and find the actual start of flow into the dead code
    submodel = IsolatedEntrySubModel(currentProgram)
    subIter = submodel.getCodeBlocksContaining(set, monitor)
    codeStarts = AddressSet()
    undefinedEntries = list()
    while subIter.hasNext():
        block = subIter.next()
        deadStart = block.getFirstStartAddress()
        codeStarts.add(deadStart)

    for startAdr in codeStarts:
        phyAdr = startAdr.getMinAddress()
        undefinedEntries.append(phyAdr)

    print("[Info] Found {} entries of undefined functions".format(len(undefinedEntries)))
    return undefinedEntries


def searchUndefinedEntryByCallsite(xref, undefinedEntries):
    listing = currentProgram.getListing()
    inst = listing.getInstructionAt(xref.getFromAddress())
    if inst is None:
        inst = listing.getInstructionContaining(xref.getFromAddress())
        if inst is None:
            print("[ERROR] Found no inst at {}".format(xref.getFromAddress()))
            return False

    curr = inst
    scanMaxSteps = 100
    while True:
        prev = curr.getPrevious()
        if prev is None or scanMaxSteps == 0:
            break

        if curr.getAddress() in undefinedEntries:
            print("[Info] Creating a missing func at entrypoint {}".format(curr.getAddress()))
            createFunction(curr.getAddress(), None)
            return True

        curr = prev
        scanMaxSteps -= 1
    return False


if __name__ == '__main__':
    begintime = time.time()
    jsonFile        = "~/AUTOSAR_rename/AUTOSAR-4.4.json"
    undefinedEntries = findUndefinedCalls()
    detFuncList = searchErrorHandlerCandidate()
    detSubFuncList  = []
    det_rename(jsonFile, detFuncList, detSubFuncList, undefinedEntries, createUndefinedFunc=True, constPropagation=True)
    print("[Info] Finish in %s" % str(datetime.timedelta(seconds = time.time() - begintime)))
