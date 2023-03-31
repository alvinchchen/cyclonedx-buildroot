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
# RLS import debmake
import shutil
import requests
import urllib3
import os
http = urllib3.PoolManager()
import urllib, json
import pypandoc
import xmltodict
import csv
import json


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

def read_openwrt_package_file(filepath):
    component = {}
    current_pakcage_name = None
    with open(filepath) as fp:
        line = fp.readline()
        while line:
            if "Package: " == line[:9]:
                current_pakcage_name = line[9:].rstrip()
                #print('packge_name: (%s)'%current_pakcage_name)
                component[current_pakcage_name] = {}
                component[current_pakcage_name]['version'] = 'openwrt'
                component[current_pakcage_name]['license'] = 'Missing license!'
                component[current_pakcage_name]['copyright'] = ''
                component[current_pakcage_name]['pkg_tar_ball_name'] = ''
            if "Version: " == line[:9]:
                component[current_pakcage_name]['version'] = line[9:].rstrip()
            if "License: " == line[:9]:
                component[current_pakcage_name]['license'] = line[9:].rstrip()
            if "Maintainer: " == line[:12]:
                component[current_pakcage_name]['copyright'] = line[12:].rstrip()
            if "Source: " == line[:8]:
                component[current_pakcage_name]['pkg_tar_ball_name'] = line[8:].rstrip()
            if "@@" == line:
                current_pakcage_name = None
            line = fp.readline()
    print("package_number : %d"%len(component))
    return component 


#where to store these two lists to be discussed!

#better add a comment in it. to be discussed!
# this two lists shall be downloaded from git.
#verified_package_list = [{ 'name': 'audit', 'version' : '2.8.4', 'approved': False }, { 'name': 'libcap-ng', 'version' : '0.7.9', 'approved': True }]

#white list to be discussed!
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

# RLS openwrt_package_info = read_openwrt_package_file("packageinfo")

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
                string = item.lstrip().rstrip().replace('\\n', '')
                if len(string):
                    copyright[string] = 1
    os.chdir(current_working_dir)
    shutil.rmtree(tmp_dir)
    copyright_text = []
    index = 1
    for i in copyright.keys():
        copyright_text.append('(%d) %s'%(index, i)) 
        index = index + 1
    print(copyright_text)
    return copyright_text, download_ok

def get_url_license(license_url):
    """Read url_license from cyclonedx """
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
    
    
        
    #scan copyright
    os.chdir(tmp_source_dir)
    os.system('wget '+ license_url)
    (nonlink_files, xml_html_files, binary_files, huge_files, counter, count_list) = debmake.scanfiles.scanfiles()
    print(nonlink_files)
    print(xml_html_files)
    if len(nonlink_files) != 0:
        data = debmake.checkdep5.checkdep5(nonlink_files, mode=3, pedantic=1)
    else:
        data = debmake.checkdep5.checkdep5(xml_html_files, mode=3, pedantic=1)
    result = license_url
    for (licenseid, licensetext, files, copyright_lines) in data:
        print(licenseid)
        print(files)
        if licenseid == 'Expat':
            licenseid = 'MIT'
        result = licenseid
    os.chdir(current_working_dir)
    shutil.rmtree(tmp_dir)
    return result

# currenty the manifest.csv file header shows
# PACKAGE,VERSION,LICENSE,LICENSE FILES,SOURCE ARCHIVE,SOURCE SITE,DEPENDENCIES WITH LICENSES
#
# example
#
# PACKAGE boost (1 to 1)
# VERSION 1.69.0 (1 to 1)
# LICENSE BSL-1.0 (many)
# LICENSE FILES LICENSE_1_0.txt (many)
# SOURCE ARCHIVE boost_1_69_0.tar.bz2 (1 to 1)
# SOURCE SITE http://downloads.sourceforge.net/project/boost/boost/1.69.0 (1 to 1)
# DEPENDENCIES WITH LICENSES skeleton-init-common [unknown] skeleton-init-systemd [unknown] toolchain-external-laird-arm [unknown] (many)
#
def build_cyclonedx_component(component):
    publisher = component['publisher']
    pkg_name = component['pkg_name']
    version = component['version']
    purl = component['purl']
    license = component['license']
    hashes = component['hashes']
    modified = component['modified']
    copyright = ""
    for item in component['copyright']:
        copyright += item
    description = component['description']
    return BomGenerator.build_component_element(publisher, pkg_name, version, description, hashes, license, purl, modified, copyright)

def openwrt_manifest_to_component(input_file):
    """Read BOM data from file path."""
    component_elements = []
    lines = []
    with open(input_file) as f:
        lines = f.readlines()
    print(f'package number : {len(lines)}')
    for i in range(0, len(lines)):
        pkg_name = lines[i].split(':')[0]
        license_name = lines[i].split(':')[1].lstrip().rstrip()
        if 'Missing license!' in license_name:
            license_name = 'Missing license!'
        component = {}
        component['publisher'] = ''
        component['pkg_name'] = pkg_name
        component['pkg_tar_ball_name'] = openwrt_package_info[pkg_name]['pkg_tar_ball_name']
        component['download_url'] = ''
        component['version'] = openwrt_package_info[pkg_name]['version']
        component['purl'] = 'pkg:fedora/' + component['pkg_name'] + '@' + component['version']
        component['license'] = openwrt_package_info[pkg_name]['license']
        component['hashes'] = []
        component['modified'] = 'false'
        component['copyright'] = openwrt_package_info[pkg_name]['copyright']
        component['description'] = ''
        component['download_fail'] = False
        component_elements.append(component)
    return component_elements


def buildroot_csv_manifest_to_component(input_file):
    """Read BOM data from a csv file typically manifest.csv."""
    with open(input_file, newline='') as csvfile:
        sheetX = csv.DictReader(csvfile)
        for row in sheetX:
            print("Package Name: ", row['PACKAGE'], "Version :", row['VERSION'])
    return


def buildroot_manifest_to_component(input_file):
    """Read BOM data from file path."""
    component_elements = []
    if input_file.split('.')[1] == 'csv':
        sheetX = pd.read_csv(input_file)
    else:
        #xslx
        xls = pd.ExcelFile(input_file)
        #parse sheet 0
        sheetX = xls.parse(0)
        
    print(f'package number : {len(sheetX)}')
    for i in range(0, len(sheetX)):
        component = {}
        component['publisher'] = ''
        component['pkg_name'] = sheetX.loc[i].values[0]
        component['pkg_tar_ball_name'] = str(sheetX.loc[i].values[4])
        component['download_url'] = str(sheetX.loc[i].values[5])
        component['version'] = str(sheetX.loc[i].values[1])
        component['purl'] = 'pkg:fedora/' + component['pkg_name'] + '@' + component['version']
        component['license'] = sheetX.loc[i].values[2]
        component['hashes'] = []
        component['modified'] = 'false'
        
        if component['license'].upper() == 'unknown'.upper():
            component['license'] = component['license'].upper()
            component['download_fail'] = False
        else: 
            copyright, download_ok = get_copyright(component['download_url'], component['pkg_tar_ball_name'])
            if not download_ok:
                #download_fail_report.append(component)
                component['download_fail'] = True
            else:
                component['download_fail'] = False
        component['copyright'] = copyright
        component['description'] = component['download_url'] + ' ' + component['pkg_tar_ball_name']
        
        component_elements.append(component)
    return component_elements


def report_csv_to_component(input_file):
    """Read BOM data from file path."""
    component_elements = []
    if input_file.split('.')[1] == 'csv':
        sheetX = pd.read_csv(input_file)
    else:
        #xslx
        xls = pd.ExcelFile(input_file)
        #parse sheet 0
        sheetX = xls.parse(0)
        
    print(f'package number : {len(sheetX)}')
    for i in range(0, len(sheetX)):
        component = {}
        component['publisher'] = ''
        component['pkg_name'] = sheetX.loc[i].values[1]
        component['pkg_tar_ball_name'] = ""
        component['download_url'] = ""
        component['version'] = str(sheetX.loc[i].values[2])
        component['purl'] = ""
        component['license'] = sheetX.loc[i].values[3]
        component['hashes'] = []
        component['modified'] = 'false'
        component['download_fail'] = False
        if str(sheetX.loc[i].values[4]) != 'nan':
            component['copyright'] = str(sheetX.loc[i].values[4])
        else:
            component['copyright'] = ''
        component['description'] = ""
        
        component_elements.append(component)
    return component_elements

def cyclonedx_to_component(input_file):

    component_elements = []
    with open(input_file) as fd:
        doc = xmltodict.parse(fd.read())
        print(doc['bom']['components']['component'])
    if type(doc['bom']['components']['component']) is not list:
        doc['bom']['components']['component'] = [doc['bom']['components']['component']]
    for item in  doc['bom']['components']['component']:
        component = {}
        
        component['publisher'] = ''
        component['pkg_name'] = item['name']
        component['version'] = item['version']
        if 'purl' in item.keys():
            component['purl'] = item['purl']
        else:
            component['purl'] = ""
        
        #component['pkg_tar_ball_name'] = item['description'].split(' ')[1]
        #component['download_url'] = item['description'].split(' ')[0]
        component['download_url'] = ''
        component['pkg_tar_ball_name'] = ''
        if 'licenses' in item.keys():
            if 'id' in item['licenses']['license'].keys():
                component['license'] = item['licenses']['license']['id']
            elif 'url' in item['licenses']['license'].keys():
                component['license'] = get_url_license(item['licenses']['license']['url'])
                if component['license'] == '__UNKNOWN__' or component['license'] == '__NO_COPYRIGHT_NOR_LICENSE__':
                    component['license'] = item['licenses']['license']['url']
            elif 'name' in item['licenses']['license'].keys():
                    component['license'] = item['licenses']['license']['name']
            else:
                component['license'] = 'xml licenses element exists but no license found!'
            """
            copyright, download_ok = get_copyright(component['download_url'], component['pkg_tar_ball_name'])
            if not download_ok:
                #download_fail_report.append(component)
                component['download_fail'] = True
            else:
                component['download_fail'] = False
            """
            component['download_fail'] = False
        else:
            component['license'] = 'License Not Found'
            component['download_fail'] = False
        if 'copyright' in item.keys():
            copyright = item['copyright']
        else:
            copyright = ''
        component['copyright'] = copyright
        if 'description' in item.keys():
            description = item['description']
        else:
            description = ''
        component['description'] = description
        component['hashes'] = []
        component['modified'] = 'false'
        component_elements.append(component)
    return component_elements

license_text_database = {}
def get_license_text(license_name):
    try:
        if license_name in license_text_database.keys():
            return license_text_database[license_name]
        else:
            license_detail = get_json_from_url("https://raw.githubusercontent.com/spdx/license-list-data/master/json/details/%s.json" % license_name)
            license_text_database[license_name] = license_detail['licenseText']
            return license_detail['licenseText']
    except:
        return "no license text"
def generate_report_object(component_list):
    """Read BOM data from file path."""
    report = {}
    ok_report = []
    error_report = []
    warning_report = []
    whitelist_report = []
    private_report = []
    download_fail_report = []
    for component in component_list:
    
        verified_result = check_verified_package_list(component['pkg_name'], component['version'])
        temp_bom = BomGenerator.build_bom([build_cyclonedx_component(component)])
        
        is_not_format_valid = not BomValidator.is_valid(temp_bom)
        is_unknown_license = component['license'] == 'UNKNOWN'
        is_not_license_in_whitelist = not component['license'] in whitelist_license
        is_osrb_verified = verified_result is not None

        if component['download_fail'] == True:
            download_fail_report.append(component)
        if is_unknown_license:
            # moxa-self-made package or private 3rdparty packages
            private_report.append(component)
        else:
            # opensource packages
            if is_not_format_valid or is_not_license_in_whitelist:
                #check if OSRB approved this package
                if is_osrb_verified:
                    if verified_result['approved']:
                        component['license'] = verified_result['license_id']
                        copyright = ''
                        index = 1
                        for i in verified_result['copyright']:
                            copyright += '(%d) %s\n'%(index, i)
                            index = index + 1
                        component['copyright'] = copyright
                        ok_report.append(component)
                    else:
                        error_report.append(component)
                else:
                    warning_report.append(component)
            else:
                whitelist_report.append(component)
            
    report['ok_report'] = ok_report
    report['error_report'] = error_report
    report['warning_report'] = warning_report
    report['whitelist_report'] = whitelist_report
    report['private_report'] = private_report
    report['download_fail_report'] = download_fail_report
    
    return report

def print_report(component_elements):
    report = generate_report_object(component_elements)
    for item in report['ok_report']:
        print('\x1b[6;30;45m[OK]\x1b[0m package: [%s %s] license [%s]'%(item['pkg_name'], item['version'], item['license']))
    for item in report['error_report']:
        print('\x1b[6;30;41m[ERROR]\x1b[0m package: [%s %s] license [%s]'%(item['pkg_name'], item['version'], item['license']))
    for item in report['warning_report']:
        print('\x1b[6;30;43m[WARNING]\x1b[0m package: [%s %s] license [%s]'%(item['pkg_name'], item['version'], item['license']))
    for item in report['whitelist_report']:
        print('\x1b[6;30;47m[WHITELIST]\x1b[0m package: [%s %s] license [%s]'%(item['pkg_name'], item['version'], item['license']))
    for item in report['private_report']:
        print('\x1b[6;30;45m[PRIVATE]\x1b[0m package: [%s %s] license [%s]'%(item['pkg_name'], item['version'], item['license']))
    for item in report['download_fail_report']:
        print('\x1b[6;37;44m[DOWNLOAD FAIL]\x1b[0m package: [%s %s] Url [%s/%s]'%(item['pkg_name'], item['version'], item['download_url'], item['pkg_tar_ball_name']))


def component_result(component):
    verified_result = check_verified_package_list(component['pkg_name'], component['version'])
    temp_bom = BomGenerator.build_bom([build_cyclonedx_component(component)])
    is_not_format_valid = not BomValidator.is_valid(temp_bom)
    is_unknown_license = component['license'] == 'UNKNOWN'
    is_not_license_in_whitelist = not component['license'] in whitelist_license
    is_osrb_verified = verified_result is not None

    # opensource packages
    if is_not_format_valid or is_not_license_in_whitelist:
        #check if OSRB approved this package
        if is_osrb_verified:
            if verified_result['approved']:
                component['license'] = verified_result['license_id']
                copyright = ''
                index = 1
                for i in verified_result['copyright']:
                    copyright += '(%d) %s\n'%(index, i)
                    index = index + 1
                component['copyright'] = copyright
                return "APPROVED"
            else:
                return "REJECTED"
        else:
            return "TO BE VERIFIED"
    else:
        return "WHITE LIST"

def report_to_row(report, result):
    markdown = ""
    for item in report:
        markdown += '|%20s|%20s|        |%s|\n' % (item['pkg_name']+ ' ' + item['version'], item['license'],result)
        #copyright = ""
        #for item2 in item['copyright']:
        #    markdown += '| | |%s|\n' % (item2)
    print(markdown)
    return markdown


def export_csv_report(component_elements, file_name):
    labels = ['RESULT', 'PACKAGE', 'VERSION' , 'LICENSE' , 'COPYRIGHT',  'DOWNLOAD URL', 'LICENSE_TEXT']
    values = []
    to_be_verified_values = []
    approved_values = []
    rejected_values = []
    white_list_values = []
    else_values = []
    
    for component in component_elements:
        #print(component)
        if component['download_url'] != '' or component['pkg_tar_ball_name'] != '':
            url = component['download_url']+'/'+component['pkg_tar_ball_name']
        else:
            url = ''
        license_text = get_license_text(component['license']).encode("ascii","ignore").decode().replace('\n', '').replace('\r', '')
        if component_result(component) == 'TO BE VERIFIED':
            row = ['TO BE VERIFIED', component['pkg_name'], "=\"%s\"" % component['version'], component['license'], component['copyright'].encode("ascii","ignore").decode(), url, license_text]
            to_be_verified_values.append(row)
        elif component_result(component) == 'APPROVED':
            row = ['APPROVED', component['pkg_name'], "=\"%s\"" % component['version'], component['license'], component['copyright'].encode("ascii","ignore").decode(), url, license_text]
            approved_values.append(row)
        elif component_result(component) == 'REJECTED':
            row = ['REJECTED', component['pkg_name'], "=\"%s\"" % component['version'], component['license'], component['copyright'].encode("ascii","ignore").decode(), url, license_text]
            rejected_values.append(row)
        elif component_result(component) == 'WHITE LIST':
            row = ['WHITE LIST', component['pkg_name'], "=\"%s\"" % component['version'], component['license'], component['copyright'].encode("ascii","ignore").decode(), url, license_text]
            white_list_values.append(row)
        else:
            row = [component_result(component), component['pkg_name'], "=\"%s\"" % component['version'], component['license'], component['copyright'].encode("ascii","ignore").decode(), url, license_text]
            else_values.append(row)

    values = to_be_verified_values + approved_values + rejected_values + white_list_values + else_values
    df = pd.DataFrame(values, columns=labels)
    df.head()
    df.to_csv("./%s.csv"%(file_name), sep=',',index=False)


def export_compliance_doc(component_elements, file_name):
    import datetime
    labels = ['RESULT', 'PACKAGE', 'VERSION' , 'LICENSE' , 'COPYRIGHT',  'DOWNLOAD URL', 'LICENSE_TEXT']
    values = []
    to_be_verified_values = []
    approved_values = []
    rejected_values = []
    white_list_values = []
    else_values = []
    compliance_doc = "OPENSOURCE COMPLIANCE DOCUMENT %s\n\n" % f"{datetime.datetime.now():%Y-%m-%d}"
    compliance_doc += "=====================================\n"
    for component in component_elements:
        #print(component)
        if component['download_url'] != '' or component['pkg_tar_ball_name'] != '':
            url = component['download_url']+'/'+component['pkg_tar_ball_name']
        else:
            url = ''
        license_text = get_license_text(component['license']).encode("ascii","ignore").decode()
        if component_result(component) == 'TO BE VERIFIED':
            row = ['TO BE VERIFIED', component['pkg_name'], component['version'], component['license'], component['copyright'].encode("ascii","ignore").decode(), url, license_text]
            to_be_verified_values.append(row)
        elif component_result(component) == 'APPROVED':
            row = ['APPROVED', component['pkg_name'], component['version'], component['license'], component['copyright'].encode("ascii","ignore").decode(), url, license_text]
            approved_values.append(row)
        elif component_result(component) == 'REJECTED':
            row = ['REJECTED', component['pkg_name'], component['version'], component['license'], component['copyright'].encode("ascii","ignore").decode(), url, license_text]
            rejected_values.append(row)
        elif component_result(component) == 'WHITE LIST':
            row = ['WHITE LIST', component['pkg_name'], component['version'], component['license'], component['copyright'].encode("ascii","ignore").decode(), url, license_text]
            white_list_values.append(row)
        else:
            row = [component_result(component), component['pkg_name'], component['version'], component['license'], component['copyright'].encode("ascii","ignore").decode(), url, license_text]
            else_values.append(row)
        
    values = to_be_verified_values + approved_values + rejected_values + white_list_values + else_values
    for item in values:
        #compliance_doc += "PACKAGE RESULT : %s\n" % item[0]
        compliance_doc += "PACKAGE NAME : %s\n" % item[1]
        compliance_doc += "PACKAGE VERSION : %s\n" % item[2]
        compliance_doc += "PACKAGE LICENSE : %s\n" % item[3]
        compliance_doc += "PACKAGE COPYRIGHT : \n"
        compliance_doc += "%s \n" % item[4]
        compliance_doc += "PACKAGE LICENSE TEXT :\n"
        compliance_doc += "%s \n" % item[6]
        compliance_doc += "=====================================\n"
    with open("%s.txt"%(file_name), "w") as text_file:
        text_file.write(compliance_doc)
def report_to_markdown(report, result):
    markdown = ""
    for item in report:
        markdown += '|%20s|%20s|        |%s|\n' % (item['pkg_name']+ ' ' + item['version'], item['license'],result)
        #copyright = ""
        #for item2 in item['copyright']:
        #    markdown += '| | |%s|\n' % (item2)
    print(markdown)
    return markdown
# python3 -m cyclonedxbuildroot.cli.generateBom -i manifest.xlsx
def export_markdown_pdf_report(component_elements, file_name):
    report = generate_report_object(component_elements)
    markdown = "OPENSOURCE REPORT\n\n"
    markdown += "### OSRB accepted packages (%d) \n" % len(report['ok_report'])
    markdown += "### OSRB rejected packages (%d) \n" % len(report['error_report'])
    markdown += "### To be verifed packages (%d) \n" % len(report['warning_report'])
    markdown += "### white list packages (%d) \n" % len(report['whitelist_report'])
    markdown += "### private packages (%d) \n" % len(report['private_report'])
    markdown += "### download fail packages (%d) \n\n" % len(report['download_fail_report'])
    markdown += "\n| Package name | License |           | Result |\n"
    markdown += "|---|---|---|---|\n"
    markdown += report_to_markdown(report['ok_report'], 'ACCEPT')
    markdown += report_to_markdown(report['error_report'], 'REJECT')
    markdown += report_to_markdown(report['warning_report'], 'TO BE VERIFIED')
    markdown += report_to_markdown(report['whitelist_report'], 'WHITE LIST')
    markdown += report_to_markdown(report['download_fail_report'], 'DOWN LOAD FAIL')
    markdown += report_to_markdown(report['private_report'], 'PRIVATE')
    with open("%s.md"%(file_name), "w") as text_file:
        text_file.write(markdown)
    pypandoc.convert_text(markdown, 'pdf', format='md', outputfile='%s.pdf'%(file_name),extra_args=['--pdf-engine=xelatex','-V', 'geometry:margin=0.2in', ])

def export_cyclonedx_sbom(component_elements, file_name):
# Generate the CycloneDX BOM and return it as an XML string
# this func will not check osrb verify result!
    bom_xml = BomGenerator.build_bom([build_cyclonedx_component(item) for item in component_elements])
    with open("%s.xml"%(file_name), 'wb') as text_file:
        text_file.write(bom_xml.encode('utf-8'))

def main():
    parser = argparse.ArgumentParser(description='CycloneDX BOM Generator')
    parser.add_argument('-i', action='store', dest='input_file', default='manifest.xlsx')
    parser.add_argument('-o', action='store', dest='output_file', default='export')
    parser.add_argument('-it', action='store', dest='input_type', default='csv')
    parser.add_argument('-ot', action='store', dest='output_type', default='csv')

    args = parser.parse_args()
    print('Input file: ' + args.input_file)
    print('Output BOM: ' + args.output_file)
    print('Input Type: ' + args.input_type)
    print('Output Type: ' + args.output_type)

    component_elements = buildroot_csv_manifest_to_component(args.input_file)

    #print(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "version": "1",
    #                       "metadata": {"time": "00:00:00 01 Jan 2023",
    #                                    "component": {"type": "firmware", "name": "Space WiFi Module",
    #                                                  "version": "1.2.3"}}}, indent=3))

    thejson = {"bomFormat": "CycloneDX", "specVersion": "1.4", "version": "1",
                           "metadata": {"time": "00:00:00 01 Jan 2023",
                                        "component": {"type": "firmware", "name": "Space WiFi Module",
                                                      "version": "1.2.3"}}}

    thejson["components"] = [ {"name": "busybox", "version": "1.2.3"}, {"name": "Linux", "version": "4.1.19"} ]

    print(json.dumps(thejson, indent=3))

main()
