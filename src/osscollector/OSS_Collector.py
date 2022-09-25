
"""
Dataset Collection Tool.
Author:		Seunghoon Woo (seunghoonwoo@korea.ac.kr)
Modified: 	December 16, 2020.
"""

import os
import sys
import subprocess
import re
import tlsh # Please intall python-tlsh

"""GLOBALS"""

currentPath	= os.getcwd()
# gitCloneURLS= currentPath + "/sample" 			# Please change to the correct file (the "sample" file contains only 10 git-clone urls)
gitCloneURLS= currentPath + "/droneURLS" 			# Please change to the correct file (the "sample" file contains only 10 git-clone urls)
clonePath 	= currentPath + "/repo_src/"		# Default path
tagDatePath = currentPath + "/repo_date/"		# Default path
resultPath	= currentPath + "/repo_functions/"	# Default path
# ctagsPath	= "/usr/local/bin/ctags" 			# Ctags binary path (please specify your own ctags path)
ctagsPath	= "/usr/bin/ctags" 			# Ctags binary path (please specify your own ctags path)

# Generate directories
shouldMake = [clonePath, tagDatePath, resultPath]
for eachRepo in shouldMake:
	if not os.path.isdir(eachRepo):
		os.mkdir(eachRepo)

def ctagsStr2json(ctagsStr):
	ctagsJson = {}
	ctagsStr = re.sub(r'/\^.*/;\"', '', ctagsStr)

	ctagsStrSplitted = ctagsStr.split("\t")

	name = ctagsStrSplitted[0]
	path = ctagsStrSplitted[1]

	ctagsJson['name'] = name
	ctagsJson['path'] = path

	for _ in ctagsStrSplitted[3:]:
		kv = _.split(":", 1)
		key = kv[0]
		value = kv[1]
		ctagsJson[key] = value

	return ctagsJson

# Generate TLSH
def computeTlsh(string):
	string 	= str.encode(string)
	hs 		= tlsh.forcehash(string)
	return hs


def removeComment(string):
	# Code for removing C/C++ style comments. (Imported from VUDDY and ReDeBug.)
	# ref: https://github.com/squizz617/vuddy
	c_regex = re.compile(
		r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
		re.DOTALL | re.MULTILINE)
	return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])

def normalize(string):
	# Code for normalizing the input string.
	# LF and TAB literals, curly braces, and spaces are removed,
	# and all characters are lowercased.
	# ref: https://github.com/squizz617/vuddy
	return ''.join(string.replace('\n', '').replace('\r', '').replace('\t', '').replace('{', '').replace('}', '').split(' ')).lower()

def hashing(repoPath):
	# This function is for hashing C/C++ functions
	# Only consider ".c", ".cc", and ".cpp" files
	possible = (".c", ".cc", ".cpp")
	
	fileCnt  = 0
	funcCnt  = 0
	lineCnt  = 0

	resDict  = {}

	for path, dir, files in os.walk(repoPath):
		for file in files:
			filePath = os.path.join(path, file)

			if file.endswith(possible):
				try:
					# Execute Ctgas command
					ctagsResult 		= subprocess.check_output(ctagsPath + ' -f - --kinds-C=* --fields=* "' + filePath + '"', stderr=subprocess.STDOUT, shell=True).decode()
					f = open(filePath, 'r', encoding = "latin1")

					# For parsing functions
					lines 		= f.readlines()
					ctagsResultSplitted	= str(ctagsResult).split('\n')

					funcSearch	= re.compile(r'{([\S\s]*)}')
					tmpString	= ""
					funcBody	= ""
					fileCnt 	+= 1

					for ctagsStr in ctagsResultSplitted:
						if not ctagsStr:
							continue

						ctagsJson = ctagsStr2json(ctagsStr)
						funcBody 	= ""

						requiredField = ['line', 'end', 'signature']
						if ctagsJson['kind'] == 'function' and all([x in ctagsJson for x in requiredField]):
							funcName = ctagsJson['name']
							funcSignature = ctagsJson['signature']
							funcScope = ctagsJson.get('scope', '')

							funcStartLine = int(ctagsJson['line'])
							funcEndLine = int(ctagsJson['end'])

							tmpString	= "".join(lines[funcStartLine - 1 : funcEndLine])

							if funcSearch.search(tmpString):
								funcBody = funcBody + funcSearch.search(tmpString).group(1)
							else:
								funcBody = " "

							funcBody = removeComment(funcBody)
							funcBody = normalize(funcBody)
							funcHash = computeTlsh(funcBody)

							if len(funcHash) == 72 and funcHash.startswith("T1"):
								funcHash = funcHash[2:]
							elif funcHash == "TNULL" or funcHash == "" or funcHash == "NULL":
								continue

							storedPath = filePath.replace(repoPath, "")
							if funcHash not in resDict:
								resDict[funcHash] = []
							resDict[funcHash].append((storedPath, funcName, funcSignature, funcScope))

							lineCnt += len(lines)
							funcCnt += 1

				except subprocess.CalledProcessError as e:
					print("Parser Error:", e)
					continue
				except Exception as e:
					print (ctagsStr)
					print (ctagsJson)
					print ("hashing Subprocess failed", e, ":", filePath)
					continue

	return resDict, fileCnt, funcCnt, lineCnt 

def indexing(resDict, title, filePath):
	# For indexing each OSS

	fres = open(filePath, 'w')
	fres.write(title + '\n')

	for hashval in resDict:
		if hashval == '' or hashval == ' ':
			continue

		fres.write(hashval)
		fres.write('\t')
		fres.write(str(resDict[hashval]))
		fres.write('\n')

	fres.close()

def main():
	with open(gitCloneURLS, 'r', encoding = "UTF-8") as fp:
		funcDateDict = {}
		lines		 = [l.strip('\n\r') for l in fp.readlines()]
		
		for eachUrl in lines:
			os.chdir(currentPath)
			repoName 	= eachUrl.split("github.com/")[1].replace(".git", "").replace("/", "@@") # Replace '/' -> '@@' for convenience
			print ("[+] Processing", repoName)

			try:
				cloneCommand 	= eachUrl + ' ' + clonePath + repoName
				cloneResult 	= subprocess.check_output(cloneCommand, stderr = subprocess.STDOUT, shell = True).decode()

				os.chdir(clonePath + repoName)

				dateCommand 	= 'git log --tags --simplify-by-decoration --pretty="format:%ai %d"'  # For storing tag dates
				dateResult		= subprocess.check_output(dateCommand, stderr = subprocess.STDOUT, shell = True).decode()
				tagDateFile 	= open(tagDatePath + repoName, 'w')
				tagDateFile.write(str(dateResult))
				tagDateFile.close()


				tagCommand		= "git tag"
				tagResult		= subprocess.check_output(tagCommand, stderr = subprocess.STDOUT, shell = True).decode()

				resDict = {}
				fileCnt = 0
				funcCnt = 0
				lineCnt = 0


				if tagResult == "":
					# No tags, only master repo

					resDict, fileCnt, funcCnt, lineCnt = hashing(clonePath + repoName)
					if len(resDict) > 0:
						if not os.path.isdir(resultPath + repoName):
							os.mkdir(resultPath + repoName)
						title = '\t'.join([repoName, str(fileCnt), str(funcCnt), str(lineCnt)])
						resultFilePath 	= resultPath + repoName + '/fuzzy_' + repoName + '.hidx' # Default file name: "fuzzy_OSSname.hidx"
						
						indexing(resDict, title, resultFilePath)

				else:
					for tag in str(tagResult).split('\n'):
						if not tag:
							continue

						# Generate function hashes for each tag (version)
						checkoutCommand	= subprocess.check_output("git checkout -f tags/" + tag, stderr = subprocess.STDOUT, shell = True)
						print("current tag: ", tag)
						resDict, fileCnt, funcCnt, lineCnt = hashing(clonePath + repoName)
						
						if len(resDict) > 0:
							if not os.path.isdir(resultPath + repoName):
								os.mkdir(resultPath + repoName)
							title = '\t'.join([repoName, str(fileCnt), str(funcCnt), str(lineCnt)])
							
							# Deal with tags that contain "/" character
							if "/" in tag:
								tag = tag.replace("/", "@@@")
							resultFilePath 	= resultPath + repoName + '/fuzzy_' + tag + '.hidx'
						
							indexing(resDict, title, resultFilePath)
						

			except subprocess.CalledProcessError as e:
				print("Parser Error:", e)
				continue
			except Exception as e:
				print ("main Subprocess failed", e)
				continue

""" EXECUTE """
if __name__ == "__main__":
	main()