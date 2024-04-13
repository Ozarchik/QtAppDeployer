import subprocess
import sys
import re, fnmatch
import os
from io import StringIO
import shutil
import pefile
from enum import Enum
from pathlib import Path

def rootPath():
    return os.path.abspath(os.sep) 

def extractNumsFromString(string:str):
	numArray = []
	for num in re.findall(r'\d+', string):
		numArray.append(int(num))
	return numArray

class CmdArgType(Enum):
    PATH = 1,
    KEY = 2


DEFAULT_PARAMETERS = {
	"qtVersion": "5.15.2",
	"qtPath": os.path.join(rootPath(), "Qt", "5.15.2"),
}


# Platform version of executable file
# https://learn.microsoft.com/ru-ru/windows/win32/api/winnt/ns-winnt-image_file_header
PLATFORM_x86 = 0x014c
PLATFORM_x64 = 0x8664
INDEPEND_SYSTEM_DLLS = ["KERNEL32.dll", "msvcrt.dll", "SHELL32.dll", "USER32.dll"]
INDEPEND_DLL_PATTERNS = [r"PythonQt.*.dll", r"python\d+.dll", r"libopencv.*.dll"]
ADDITIONAL_DLLS = ["libwinpthread-1.dll"]
system32Files = os.listdir(os.path.join(rootPath(), "Windows", "System32"))

# TEST ----------------------------------------
pathToTestExe = "C:\\MyProjects\\veryslot2_clearDevelop\\veryslot23\\appdesktop\\VerySlot2.exe"
testCmdArgs = ["test.exe", pathToTestExe, "-32"]
# TEST ----------------------------------------


class Deployer:	
	def __init__(self, args):
		self.depends = []
		self.findedDependenciesPath = []
		self.qtDepends = []
		self.commonDepends = []
		self.findedDepends = []
		self.qtVersion = DEFAULT_PARAMETERS["qtVersion"]
		self.qtLibsPath = DEFAULT_PARAMETERS["qtPath"]
		

		self.cmdArguments = args		
		self.keyArgs = self.getFilteredCmdAguments(self.cmdArguments, CmdArgType.KEY)
		self.filename = self.cmdArguments[0]
		self.filePath = self.cmdArguments[1]

		self.appInfo = pefile.PE(self.filePath)

		self.setPlatformVersion(self.getPlatformVersionOnHex())
		self.scanner = Scanner()
		self.scanner.setupQtMingwPath(self.platformVersion)

	def start(self):
		self.findDependencies(self.filePath)
		print("\n------------------------------------------- Found next dependencies -------------------------------------------")
		print("Qt libs:\t", self.qtDepends)
		print("App libs:\t", self.commonDepends)
		print("---------------------------------------------------------------------------------------------------------------\n")
		parentDir = Path(self.filePath).parents[1]
		appLibsPath = self.scanner.getAppLibsByFullScanPath(parentDir)

		for lib in appLibsPath:
			self.findDependencies(lib)


		self.removeIndependedAppLibs()
		self.findedDependenciesPath.extend(self.getAllAppDependenciesPath(appLibsPath))
		self.findedDependenciesPath.extend(self.getAllQtDependenciesPath())

		self.copyAllDependenciesToExeDir()

	def findDependencies(self, filePath):
		print("Search depends on: ", filePath)
		pe = pefile.PE(filePath)
		for dependency in pe.DIRECTORY_ENTRY_IMPORT:
			lib = dependency.dll.decode("utf-8")

			
			if (lib in INDEPEND_SYSTEM_DLLS):
				continue		

			if (lib.lower() in map(lambda name: name.lower(), system32Files)):
				continue

			if (lib.startswith("Qt")):
				if (lib not in self.qtDepends):
					self.qtDepends.append(lib)
			else:
				if ((lib not in self.commonDepends)):
					self.commonDepends.append(lib)

	def copyAllDependenciesToExeDir(self):
		destDir = Path(self.filePath).parents[0]

		for libPath in self.findedDependenciesPath:
			shutil.copy(libPath, destDir)

		shutil.copytree(os.path.join(self.scanner.getQtMingwPath(), "plugins", "platforms"), os.path.join(destDir, "platforms"), dirs_exist_ok=True) 

		for lib in ADDITIONAL_DLLS:
			shutil.copy(os.path.join(self.scanner.getQtMingwPath(), "bin", lib), destDir)

	def getPlatformVersionOnHex(self):
		return self.appInfo.FILE_HEADER.Machine

	def setPlatformVersion(self, version:hex):
		if (version == PLATFORM_x86):
			self.platformVersion = "32"
		elif (version == PLATFORM_x64):
			self.platformVersion = "64"

		print(f"platform version: x{self.platformVersion}")

	def getFilteredCmdAguments(self, args, type:CmdArgType):
		if (type == CmdArgType.PATH):
			args = [item for item in args if not item.startswith("-")]
		elif (type == CmdArgType.KEY):
			args = [item for item in args if item.startswith("-")]

		return args
	

	def getAllAppDependenciesPath(self, appLibsPath:list):
		result = []
		
		for lib in self.commonDepends:
			for libPath in appLibsPath:
				if libPath not in result:
					if lib == os.path.basename(libPath):
						result.append(libPath)
						break
					elif lib in self.getListOfQtLibs():
						result.append(os.path.join(self.scanner.getQtMingwPath(), "bin", lib))
						break

		return result



	def getAllQtDependenciesPath(self):
		qtLibsPath = os.path.join(self.scanner.getQtMingwPath(), "bin")
		listOfQtDependsPath = [os.path.join(qtLibsPath, qtLib) for qtLib in self.qtDepends]
		return listOfQtDependsPath

	def getListOfQtLibs(self):
		return os.listdir(os.path.join(self.scanner.getQtMingwPath(), "bin"))

	def removeIndependedAppLibs(self):
		for pattern in INDEPEND_DLL_PATTERNS:
			regex = re.compile(pattern)
			for dependLib in self.commonDepends[::-1]: # reverse iterate list for correct remove items
				result = regex.match(dependLib)
				if (result != None):
					self.commonDepends.remove(dependLib)


class Scanner:
	def __init__(self):
		self.currentPath = rootPath()

	def isDirectoryExists(self, path, directory):
		isDirExist = os.path.isdir(os.path.join(path, directory))
		return isDirExist

	def setCurrentPath(self, path):
		self.currentPath = path

	def setupQtMingwPath(self, platformVersion:int):
		mingwDirs = os.listdir(DEFAULT_PARAMETERS["qtPath"])
		if (len(mingwDirs) > 0):
			highestMingwVersion = extractNumsFromString(mingwDirs[0])[0]
			index = 0
			for i, mingwDir in enumerate(range(len(mingwDirs))):
				if int(extractNumsFromString(mingwDirs[i])[0]) > highestMingwVersion:
					if (extractNumsFromString(mingwDirs[i])[1] == platformVersion):
						index = i
		else:
			raise Exception("Not found any mingw directory")

		self.mingwPath = os.path.join(DEFAULT_PARAMETERS["qtPath"], mingwDirs[index])

	def getQtMingwPath(self):
		return self.mingwPath

	def getAppLibsByFullScanPath(self, path:str):

		libNamePattern = "*.dll"
		result = []
		for root, dirs, files in os.walk(path):
			for file in files:
				if fnmatch.fnmatch(file, libNamePattern):
					result.append(os.path.join(root, file))
		return result


deployer = Deployer(testCmdArgs)
deployer.start()
