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
#get copyright
import debmake
import shutil
import requests
import urllib3
import os
http = urllib3.PoolManager()
import urllib, json

def get_json_from_url(url):
    response = urllib.request.urlopen(url)
    return json.loads(response.read())
    

def print_list(list):
    for item in list:
        print(item)

def sanitized_license_name(license):
    #license name in buildroot is not well formatted for spdx.
    sanitized_license = re.sub('\(.*?\)', '', license)
    sanitized_license = sanitized_license.split(' or')[0]
    sanitized_license = sanitized_license.split(' ')[0]
    sanitized_license = sanitized_license.split(',')[0]
    return sanitized_license

# this two lists shall be downloaded from git.
#verified_package_list = [{ 'name': 'audit', 'version' : '2.8.4', 'approved': False }, { 'name': 'libcap-ng', 'version' : '0.7.9', 'approved': True }]

"""
whitelist_license = ['Apache-2.0',\
    'BSD-2-Clause',\
    'BSD-2-Clause-FreeBSD',\
    'BSD-3-Clause',\
    '0BSD',\
    'ISC',\
    'MIT',\
    'X11',\
    'GPL-2.0',\
    'GPL-2.0+',\
    'LGPL-2.1',\
    'LGPL-2.1+',\
    'GPL-2.0-only',\
    'GPL-2.0-or-later',\
    'LGPL-2.1-only',\
    'LGPL-2.1-or-later']
"""
verified_package_list = get_json_from_url("https://raw.githubusercontent.com/alvinchchen/verified_package_list/master/verified_package_list.json")

whitelist_license = get_json_from_url("https://github.com/alvinchchen/verified_package_list/raw/master/whitelist.json")


def check_verified_package_list(name, version):
    for pkg in verified_package_list:
        if name == pkg['name'] and version ==pkg['version']:
            return pkg
    return None

def get_copyright(download_url, tarball_name):
    """Read copyright data from file."""
    copyright = {}
    download_ok = True
    tmp_dir = './tmp/'
    report = ''
    try:
        shutil.rmtree(tmp_dir)
    except:
        pass
    os.mkdir(tmp_dir)
    tmp_source_dir = './tmp/src/'
    os.mkdir(tmp_source_dir)
    current_working_dir = os.getcwd()
    
    local_download_path = './' + tarball_name
    download_url = download_url + "/" + tarball_name
    if not os.path.isfile(tarball_name):
        print('no tarball')
        os.system('wget '+ download_url)
    if os.path.isfile(local_download_path):
        os.system('tar xvf '+ local_download_path + ' -C ' + tmp_source_dir)
    else:
        download_ok = False
    #scan copyright
    os.chdir(tmp_source_dir)
    (nonlink_files, xml_html_files, binary_files, huge_files, counter, count_list) = debmake.scanfiles.scanfiles()
    data = debmake.checkdep5.checkdep5(nonlink_files, mode=3, pedantic=1)
    
    for (licenseid, licensetext, files, copyright_lines) in data:
        copyright_line = copyright_lines[11:]
        if '__NO_COPYRIGHT__' not in copyright_line \
            and '__INITIAL_' not in  copyright_line \
            and '__NO_COPYRIGHT_NOR_LICENSE__' not in copyright_line \
            and '__SHORT_LINE__' not in copyright_line \
            and '__LONG_LINE__' not in copyright_line \
            and '__MANY_NON_ASCII__' not in copyright_line :
            
            copyright_string_list = copyright_line.split('\n')
            
            for item in copyright_string_list:
                string = item.lstrip().rstrip()
                if len(string):
                    copyright[string] = 1
    os.chdir(current_working_dir)
    shutil.rmtree(tmp_dir)
    copyright_text = ''
    index = 1
    for i in copyright.keys():
        copyright_text = copyright_text + '(%d)%s\n'%(index, i) 
        index = index + 1
    print(copyright_text)
    return copyright_text, download_ok

def read_buildroot_manifest(input_file):
    """Read BOM data from file path."""
    print(f'Generating CycloneDX BOM from buildroot {input_file}')
    component_elements = []
    ok_report = ['\x1b[6;30;42m' + "///// Package list approved by OSRB /////"]
    error_report = ['\x1b[6;30;41m' + "///// Package list rejected by OSRB /////"]
    warning_report = ['\x1b[6;30;43m' + "///// Package list has to be verified by OSRB /////"]
    whitelist_report = ['\x1b[6;30;47m' + "///// Package list in whitelist by OSRB /////"]
    private_report = ['\x1b[6;30;45m' + "///// Packages are private /////"]
    download_fail_report = ['\x1b[6;37;44m' + "///// Packages tarball download fail /////"]
    try:
        if input_file.split('.')[1] == 'csv':
            sheetX = pd.read_csv(input_file)
        else:
            #xslx
            xls = pd.ExcelFile(input_file)
            #parse sheet 0
            sheetX = xls.parse(0)
            
        print(f'package number : {len(sheetX)}')
        for i in range(0, len(sheetX)):
            
            publisher = ''
            pkg_name = sheetX.loc[i].values[0]
            pkg_tar_ball_name = str(sheetX.loc[i].values[4])
            download_url = str(sheetX.loc[i].values[5])
            purl = 'pkg:' + str(sheetX.loc[i].values[5]) + '/' + str(sheetX.loc[i].values[4])
            version = str(sheetX.loc[i].values[1])
            license = sheetX.loc[i].values[2]
            hashes = []
            modified = 'false'
            #license name in buildroot is not well formatted for spdx.
            #sanitized_license = re.sub('\(.*?\)', '', license)
            #sanitized_license = sanitized_license.split(' or')[0]
            #sanitized_license = sanitized_license.split(' ')[0]
            #sanitized_license = sanitized_license.split(',')[0]
            
            sanitized_license = license
            if sanitized_license == 'unknown':
                sanitized_license = sanitized_license.upper()
            
            if sanitized_license != 'UNKNOWN':
                copyright, download_ok = get_copyright(download_url, pkg_tar_ball_name)
                if not download_ok:
                    download_fail_report.append('\x1b[6;37;44m' + '[DOWNLOAD FAIL]' + '\x1b[0m'+ f' package: [{pkg_name} {version}] download_url [{download_url}/{pkg_tar_ball_name}]')
            else:
                copyright = ""
                
            description = copyright
            print('Processing Package: ' + pkg_name)
            print('Processing Package License: ' + sanitized_license)
            component = BomGenerator.build_component_element(publisher, pkg_name, version, description, hashes, sanitized_license, purl, modified, copyright)
            temp_bom = BomGenerator.build_bom([component])
            is_unknown_license = sanitized_license == 'UNKNOWN'
            is_not_format_valid = not BomValidator.is_valid(temp_bom)
            is_not_license_in_whitelist = not sanitized_license in whitelist_license
            
            verified_result = check_verified_package_list(pkg_name, version)
            
            is_osrb_verified = verified_result is not None
            
            if is_unknown_license:
                # moxa-self-made package or private 3rdparty packages
                private_report.append('\x1b[6;30;45m' + '[PRIVATE  ]' + '\x1b[0m'+ f' package: [{pkg_name} {version}] license [{sanitized_license}]')
            else:
                # opensource packages
                if is_not_format_valid or is_not_license_in_whitelist:
                    #check if OSRB approved this package
                    if is_osrb_verified:
                        if verified_result['approved']:
                            ok_report.append('\x1b[6;30;42m' + '[OK]' + '\x1b[0m'+ f' package: [{pkg_name} {version}] license [{sanitized_license}]')
                        else:
                            error_report.append('\x1b[6;30;41m' + '[ERROR]' + '\x1b[0m'+ f' package: [{pkg_name} {version}] license [{sanitized_license}]')
                    else:
                        warning_report.append('\x1b[6;30;43m' + '[WARNING]' + '\x1b[0m'+ f' package: [{pkg_name} {version}] license [{sanitized_license}]')
                else:
                    whitelist_report.append('\x1b[6;30;47m' + '[WHITELIST]' + '\x1b[0m'+ f' package: [{pkg_name} {version}] license [{sanitized_license}]')
            component_elements.append(component)
            #break
            
    except Exception as error:
        print('This manifest file format is not valid:')
        print(error)
        raise error
    print('---------------------------------------')
    print('report:')
    print_list(ok_report)
    print_list(error_report)
    print_list(warning_report)
    print_list(whitelist_report)
    print_list(private_report)
    print_list(download_fail_report)
    print('APPROVED: %d REJECTED: %d WARNING: %d WHITELIST: %d PRIVATE: %d DOWNLOAD_FAIL: %d' % \
        (len(ok_report) -1, len(error_report) -1, len(warning_report) -1, len(whitelist_report) -1, len(private_report) -1, len(download_fail_report) -1))
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
