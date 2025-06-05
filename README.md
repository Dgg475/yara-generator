# YARA Rule Generator

A Python script designed to generate YARA rules from a set of sample files. This tool extracts common strings from the provided files, applies file-type specific filtering, and constructs a YARA rule with detailed metadata.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Directory Structure](#directory-structure)
- [Modules](#modules)
- [Running the Script](#running-the-script)
- [Example](#example)
- [Contributing](#contributing)
- [License](#license)

## Overview

This script automates the process of creating YARA rules by analyzing a collection of files, typically malware samples or similar datasets. It supports various file types including executables (exe), PDFs, emails (eml), office documents, and JavaScript/HTML files. The script uses the `pefile` library for PE file analysis, extracts strings, removes common imports or irrelevant data, and generates a YARA rule based on the common attributes found across the samples.

## Prerequisites

- Python 3.x
- `pefile` library (can be installed via pip or placed in the modules directory)


 ```
pip install pefile
 ```


Command Line Arguments
InputDirectory: Path to the directory containing the sample files.
-r, --RuleName: Name of the YARA rule to be generated (must start with a letter, no spaces).
-a, --Author: Name of the author (default: "Anonymous").
-d, --Description: Description of the YARA rule (default: "No Description Provided").
-t, --Tags: Comma-separated tags for the rule (optional).
-v, --Verbose: If set, prints the generated rule to the console.
-f, --FileType: Type of files being analyzed. Options are unknown, exe, pdf, email, office, js-html.

example: 
```
python3 yarafull.py samples -r Myrule3 -f exe -a "Mino761" -d "test" -t malware,exe -v

```
