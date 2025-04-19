#!/usr/bin/env python3
"""
Full YARA Rule Generator – A tool to generate YARA rules based on a sample set of files.
It extracts strings from samples, applies file-type filtering (including using PE imports,
email header parsing, etc.), and produces a YARA rule with metadata.
"""

import os
import sys
import re
import argparse
import hashlib
import random
import email
from datetime import datetime

# Ensure the modules directory is in the system path.
pathname = os.path.abspath(os.path.dirname(sys.argv[0]))
sys.path.append(os.path.join(pathname, 'modules'))

# Make sure required module pefile is available.
try:
    import pefile
except ImportError:
    print("[!] PEfile not installed or present in ./modules directory")
    sys.exit(1)

# Global list to store the MD5 hashes of files processed.
hashList = []


def md5sum(filename):
    """Compute and return the MD5 hash for the given file."""
    with open(filename, 'rb') as fh:
        m = hashlib.md5()
        while chunk := fh.read(8192):
            m.update(chunk)
    return m.hexdigest()


def getFiles(workingdir):
    """
    Scan the given directory for files, calculate their MD5 hashes,
    and store them in a dictionary.
    Ignores hidden files.
    """
    global hashList
    fileDict = {}
    hashList = []
    for f in os.listdir(workingdir):
        filepath = os.path.join(workingdir, f)
        if os.path.isfile(filepath) and not f.startswith("."):
            fhash = md5sum(filepath)
            fileDict[fhash] = filepath
            hashList.append(fhash)
    if len(fileDict) == 0:
        print(f"[!] No Files Present in \"{workingdir}\"")
        sys.exit(1)
    return fileDict


def linkSearch(text):
    """
    Search for URLs using a regex.
    Matches protocols like ftp, hxxp (commonly used in obfuscation), etc.
    """
    url_regex = re.compile(
        r'(?:ftp|hxxp)[s]?://(?:[a-zA-Z0-9\$\-_@.&+]|[!*$$$$,]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        re.I
    )
    urls = list(set(url_regex.findall(text)))
    return urls


def getStrings(filename):
    """
    Extract printable strings from a file. Both ASCII and wide/Unicode strings
    are extracted. Also appends any URLs found in the file.
    """
    try:
        with open(filename, 'rb') as f:
            data = f.read()
        # Regular expression for ASCII strings.
        chars = r"A-Za-z0-9/\-:.,_$%@'()\\\{\};\]$$<> "
        regexp = r'[{0}]{{6,100}}'.format(chars)
        pattern = re.compile(regexp)
        strlist = pattern.findall(data)

        # Extract wide (Unicode) strings.
        unicode_pattern = re.compile(r'(?:[\x20-\x7E]\x00){6,100}')
        unicodelist = unicode_pattern.findall(data)

        allstrings = unicodelist + strlist

        # Check and add URLs if present.
        urls = linkSearch(data)
        if urls:
            allstrings.extend(urls)

        if allstrings:
            return list(set(allstrings))
        else:
            print(f"[!] No Extractable Attributes Present in Hash: {md5sum(filename)}. Please remove it from the sample set and try again!")
            sys.exit(1)
    except Exception as e:
        print(f"[!] Error extracting strings from file {filename}: {e}")
        sys.exit(1)


def exeImportsFuncs(filename, allstrings):
    """
    For a given PE executable, use pefile to extract imported DLLs
    and function names. These strings are then removed from the list of
    extracted strings.
    """
    try:
        pe = pefile.PE(filename)
        importlist = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                # Decode DLL names if in bytes.
                dll_name = entry.dll.decode('utf-8') if isinstance(entry.dll, bytes) else entry.dll
                importlist.append(dll_name)
                for imp in entry.imports:
                    if imp.name:
                        imp_name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else imp.name
                        importlist.append(imp_name)
        # Remove these import-related strings from the overall string list.
        for imp in importlist:
            if imp in allstrings:
                try:
                    allstrings.remove(imp)
                except Exception:
                    pass
        if len(allstrings) > 0:
            return list(set(allstrings))
        else:
            print(f'[!] No Extractable Attributes Present in Hash: {md5sum(filename)}. Please remove it from the sample set and try again!')
            sys.exit(1)
    except Exception:
        return allstrings


def emailParse(filename):
    """
    Parse an EML file; extract header values (omitting common, non-informative keys),
    walk through the parts in search of text (plain or HTML) and attachments,
    and return a list of strings that can later be used as signature material.
    """
    try:
        def emailStrings(text):
            chars = r"A-Za-z0-9/\-:_$%@'()\\\{\};$$\["
            regexp = r'[{0}]{{6,100}}'.format(chars)
            pattern = re.compile(regexp)
            return pattern.findall(text)

        # List of header keys that are not useful for signatures.
        uselesskeys = [
            'DKIM-Signature', 'X-SENDER-REPUTATION', 'References', 'To',
            'Delivered-To', 'Received', 'Message-ID', 'MIME-Version',
            'In-Reply-To', 'Date', 'Content-Type', 'X-Original-To'
        ]
        with open(filename, 'r', errors='ignore') as emailfile:
            msg = email.message_from_file(emailfile)
        emaildict = dict(msg.items())
        if len(emaildict) == 0:
            print(f'[!] This File is not an EML File: {md5sum(filename)}. Please remove it from the sample set or select proper filetype!')
            sys.exit(1)
        for key in uselesskeys:
            if key in emaildict:
                del emaildict[key]

        emaillist = []
        for part in msg.walk():
            part_ct = str(part.get_content_type())
            if "plain" in part_ct:
                bodyplain = part.get_payload(decode=True)
                if bodyplain:
                    try:
                        bodyplain = bodyplain.decode('utf-8', errors='ignore')
                    except Exception:
                        pass
                    textlinks = linkSearch(bodyplain)
                    if textlinks:
                        emaildict['Body-Links'] = textlinks
            if "html" in part_ct:
                bodyhtml = part.get_payload(decode=True)
                if bodyhtml:
                    try:
                        bodyhtml = bodyhtml.decode('utf-8', errors='ignore')
                    except Exception:
                        pass
                    htmllinks = linkSearch(bodyhtml)
                    if htmllinks:
                        emaildict['Body-Links'] = htmllinks
            if "application" in part_ct:
                if part.get_filename():
                    emaildict['attachmentName'] = part.get_filename()
        for key, value in emaildict.items():
            if isinstance(value, list):
                emaillist.extend(value)
            else:
                emaillist.append(value)
        return emaillist
    except Exception:
        print(f'[!] This File is not an EML File: {md5sum(filename)}. Please remove it from the sample set or select proper filetype!')
        sys.exit(1)


def findCommonStrings(fileDict, filetype):
    """
    Given a dictionary in which each key represents a file’s hash and its value
    the list of extracted strings, randomly select one file’s string set as a baseline.
    Then, identify which strings are common to every file (sample) in the set.
    Finally, load filetype-specific blacklist and regex-blacklist files (if available)
    from the modules directory and remove any matches from the result.
    """
    baseStringList = random.choice(list(fileDict.values()))
    finalStringList = []
    matchNumber = len(fileDict)
    for s in baseStringList:
        sNum = 0
        for value in fileDict.values():
            if s in value:
                sNum += 1
        if sNum == matchNumber:
            finalStringList.append(s)

    # Load filetype-specific blacklists.
    blacklist_path = os.path.join(pathname, 'modules', filetype + '_blacklist.txt')
    regex_blacklist_path = os.path.join(pathname, 'modules', filetype + '_regexblacklist.txt')
    try:
        with open(blacklist_path, 'r') as f:
            blacklist = f.read().splitlines()
    except Exception:
        blacklist = []
    try:
        with open(regex_blacklist_path, 'r') as f:
            regblacklist = f.read().splitlines()
    except Exception:
        regblacklist = []

    # Remove strings matching the plain blacklist.
    finalStringList = [s for s in finalStringList if s not in blacklist]
    # Remove strings matching regex blacklist patterns.
    regmatchlist = []
    for regblack in regblacklist:
        try:
            regex = re.compile(regblack)
        except Exception:
            continue
        for string in finalStringList:
            if regex.search(string):
                regmatchlist.append(string)
    for match in set(regmatchlist):
        if match in finalStringList:
            finalStringList.remove(match)

    return finalStringList


def buildYara(options, strings, hashes):
    """
    Construct the YARA rule from the extracted strings and file hashes.
    The rule includes metadata (author, date, description, file hashes) and a series of
    string declarations. The condition is set as either "any of them" (for emails)
    or a specified number of strings.
    """
    date = datetime.now().strftime("%Y-%m-%d")
    randStrings = []
    try:
        for i in range(1, 20):
            randStrings.append(random.choice(strings))
    except IndexError:
        print('[!] No Common Attributes Found For All Samples, Please be more selective')
        sys.exit(1)

    # Prioritize additional signature material for emails
    if options.FileType.lower() == 'email':
        for s in strings:
            if "@" in s or "." in s:
                randStrings.append(s)

    # Remove duplicates.
    randStrings = list(set(randStrings))

    rule_filename = options.RuleName + ".yar"
    with open(rule_filename, "w") as ruleOutFile:
        ruleOutFile.write(f"rule {options.RuleName}")
        if options.Tags:
            ruleOutFile.write(f" : {options.Tags}")
        ruleOutFile.write("\n{\n")
        ruleOutFile.write("meta:\n")
        ruleOutFile.write(f"\tauthor = \"{options.Author}\"\n")
        ruleOutFile.write(f"\tdate = \"{date}\"\n")
        ruleOutFile.write(f"\tdescription = \"{options.Description}\"\n")
        for i, h in enumerate(hashes):
            ruleOutFile.write(f"\thash{i} = \"{h}\"\n")
        ruleOutFile.write(f"\tsample_filetype = \"{options.FileType}\"\n")
        ruleOutFile.write("\tyaragenerator = \"https://github.com/Dgg475/\"\n")
        ruleOutFile.write("strings:\n")
        for s in randStrings:
            # If a string contains null bytes, output it as wide.
            if "\x00" in s:
                cleaned = s.replace("\\", "\\\\").replace('"', '\\"').replace("\x00", "")
                ruleOutFile.write(f"\t$string{randStrings.index(s)} = \"{cleaned}\" wide\n")
            else:
                cleaned = s.replace("\\", "\\\\").replace('"', '\\"')
                ruleOutFile.write(f"\t$string{randStrings.index(s)} = \"{cleaned}\"\n")
        ruleOutFile.write("condition:\n")
        if options.FileType.lower() == "email":
            ruleOutFile.write("\tany of them\n")
        else:
            ruleOutFile.write(f"\t{len(randStrings) - 1} of them\n")
        ruleOutFile.write("}\n")
    return


# Filetype-specific execution paths.
def unknownFile(fileDict):
    for fhash, path in fileDict.items():
        fileDict[fhash] = getStrings(path)
    finalStringList = findCommonStrings(fileDict, 'unknown')
    return finalStringList


def exeFile(fileDict):
    for fhash, path in fileDict.items():
        fileDict[fhash] = exeImportsFuncs(path, getStrings(path))
    finalStringList = findCommonStrings(fileDict, 'exe')
    return finalStringList


def pdfFile(fileDict):
    for fhash, path in fileDict.items():
        fileDict[fhash] = getStrings(path)
    finalStringList = findCommonStrings(fileDict, 'pdf')
    return finalStringList


def emailFile(fileDict):
    for fhash, path in fileDict.items():
        fileDict[fhash] = emailParse(path)
    finalStringList = findCommonStrings(fileDict, 'email')
    return finalStringList


def officeFile(fileDict):
    for fhash, path in fileDict.items():
        fileDict[fhash] = getStrings(path)
    finalStringList = findCommonStrings(fileDict, 'office')
    return finalStringList


def jshtmlFile(fileDict):
    for fhash, path in fileDict.items():
        fileDict[fhash] = getStrings(path)
    finalStringList = findCommonStrings(fileDict, 'jshtml')
    return finalStringList


def main():
    filetypeoptions = ['unknown', 'exe', 'pdf', 'email', 'office', 'js-html']
    parser = argparse.ArgumentParser(description="YaraGenerator")
    parser.add_argument("InputDirectory", help="Path to files to create Yara rule from")
    parser.add_argument("-r", "--RuleName", required=True, help="Enter a Rule/Alert Name (No Spaces + Must Start with a letter)")
    parser.add_argument("-a", "--Author", default="Anonymous", help="Enter Author Name")
    parser.add_argument("-d", "--Description", default="No Description Provided", help="Provide a description of the Yara rule")
    parser.add_argument("-t", "--Tags", default="", help="Apply tags to the Yara rule for easy reference")
    parser.add_argument("-v", "--Verbose", default=False, action="store_true", help="Print finished rule to standard out")
    parser.add_argument("-f", "--FileType", required=True, choices=filetypeoptions, help="Select sample set filetype; options: " + ', '.join(filetypeoptions))
    if len(sys.argv) <= 3:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()

    # Validate rule name (must not have spaces and must start with an alphabetic character).
    if " " in options.RuleName or not options.RuleName[0].isalpha():
        print("[!] Rule Name cannot contain spaces or begin with a non-alpha character")
        sys.exit(1)

    fileDict = getFiles(options.InputDirectory)
    print(f"\n[+] Generating Yara Rule {options.RuleName} from files located in: {options.InputDirectory}")

    filetype = options.FileType.lower()
    if filetype == 'exe':
        finalStringList = exeFile(fileDict)
    elif filetype == 'pdf':
        finalStringList = pdfFile(fileDict)
    elif filetype == 'email':
        finalStringList = emailFile(fileDict)
    elif filetype == 'office':
        finalStringList = officeFile(fileDict)
    elif filetype in ['js-html', 'jshtml']:
        finalStringList = jshtmlFile(fileDict)
    else:
        finalStringList = unknownFile(fileDict)

    global hashList
    buildYara(options, finalStringList, hashList)
    print(f"\n Yara Rule Generated: {options.RuleName}.yar\n")
    print(f"   Files Examined: {hashList}")
    print(f"   Author Credited: {options.Author}")
    print(f"   Rule Description: {options.Description}")
    if options.Tags:
        print(f"   Rule Tags: {options.Tags}\n")
    if options.Verbose:
        print(" Rule Below:\n")
        with open(options.RuleName + ".yar", 'r') as donerule:
            print(donerule.read())

    


if __name__ == "__main__":
    main()
