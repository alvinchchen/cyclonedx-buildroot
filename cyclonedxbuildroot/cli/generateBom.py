#!/usr/bin/env python
# encoding: utf-8

# This file is part of CycloneDX Python module.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) Steve Springett. All Rights Reserved.
# Copyright (c) 2020 Alvin Chen. All Rights Reserved.
# the main reason of change here is to generate a import-able bom.xml for dependency-track

import argparse
import pandas as pd
import re
import xmlschema
from cyclonedxbuildroot import BomGenerator
from cyclonedxbuildroot import BomValidator

def read_buildroot_manifest(input_file):
    """Read BOM data from file path."""
    print(f'Generating CycloneDX BOM from buildroot {input_file}')
    component_elements = []
    try:
        xls = pd.ExcelFile(input_file)
        #parse sheet 0
        sheetX = xls.parse(0)
        print(f'package number : {len(sheetX)}')
        for i in range(0, len(sheetX)):

            publisher = ''
            pkg_name = sheetX.loc[i].values[0]
            url = 'pkg:' + str(sheetX.loc[i].values[5]) + '/' + str(sheetX.loc[i].values[4])
            version = str(sheetX.loc[i].values[1])
            license = sheetX.loc[i].values[2]
            hashes = []
            description = sheetX.loc[i].values[6]
            modified = 'false'

            #license name in buildroot is not well formatted for spdx.
            sanitized_license = re.sub('\(.*?\)', '', license)
            sanitized_license = sanitized_license.split('or')[0]
            sanitized_license = sanitized_license.split(' ')[0]
            sanitized_license = sanitized_license.split(',')[0]
            
            if sanitized_license == 'unknown':
                sanitized_license = sanity_license.upper()
                
            print('Processing Package: ' + sheetX.loc[i].values[0])
            print('Processing Package License: ' + sanitized_license)
            component = BomGenerator.build_component_element(publisher, pkg_name, version, description, hashes, sanitized_license, url, modified)
            temp_bom = BomGenerator.build_bom([component])
            if not BomValidator.is_valid(temp_bom):
                print('This package is not valid')
                print(temp_bom)
                quit(-1)
            component_elements.append(component)
    except:
        print('This manifest file format is not valid')
        quit(-1)
    return component_elements

# python3 -m cyclonedxbuildroot.cli.generateBom.py -i manifest.xlsx
def main():
    parser = argparse.ArgumentParser(description='CycloneDX BOM Generator')
    parser.add_argument('-i', action='store', dest='input_file', default='manifest.xlsx')
    parser.add_argument('-o', action='store', dest='output_file', default='bom.xml')
    args = parser.parse_args()
    print('Input file: ' + args.input_file)
    
    print('Output BOM: ' + args.output_file)
    component_elements = read_buildroot_manifest(args.input_file)
    # Generate the CycloneDX BOM and return it as an XML string
    bom_xml = BomGenerator.build_bom(component_elements)
    with open(args.output_file, 'wb') as text_file:
        text_file.write(bom_xml.encode('utf-8'))

main()
