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
# the main reason of change here is to generate an import-able bom.xml for dependency-track

import argparse
from datetime import datetime, tzinfo
from typing import Any, Type

from cyclonedxbuildroot import BomGenerator
from cyclonedxbuildroot import BomValidator
import csv
import json


# Buildroot manifest.csv file header shows the following header row
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

def create_json_from_sbom(args):
    sbom_time = datetime.utcnow()
    # Insert the CycloneDX header info for the user supplied component
    thejson = {"bomFormat": "CycloneDX", "specVersion": "1.4", "version": "1",
               "metadata": {"time": (str(sbom_time)+" UTC"),
                            "component": {"type": "firmware",
                                          "name": args.input_name,
                                          "version": args.component_version}}}

    final_component_details = list("")
    # Buildroot CSV file supplies software package data in each row. Any change to that map of data will break
    # the resulting JSON.
    with open(args.input_file, newline='') as csvfile:
        sheetX = csv.DictReader(csvfile)
        for row in sheetX:
            try:
                purl_info: str | Any = "pkg:generic/" + row['PACKAGE'] + "-" + row['VERSION'] + "?download_url=" + row[
                    'SOURCE SITE'] + row['SOURCE ARCHIVE']
                license_list_info = list("")
                set_of_license_info = {"expression": row['LICENSE']}
                license_list_info.append(set_of_license_info)
                set_of_component_details = {"type": "library", "name": row['PACKAGE'], "version": row['VERSION'],
                                            "licenses": license_list_info, "purl": purl_info}
                final_component_details.append(set_of_component_details)
            except KeyError:
                print("The input file header does not contain the expected data in the first row of the file.")
                print(
                    "Expected PACKAGE,VERSION,LICENSE,LICENSE FILES,SOURCE ARCHIVE,SOURCE SITE,DEPENDENCIES WITH LICENSES")
                print("Found the following in the csv file first row:", row)
                print("Cannot continue with the provided input file. Exiting.")
                exit(-1)
    thejson["components"] = [final_component_details]
    outputfile = open(args.output_file, mode='w')
    json.dump(thejson, outputfile, indent=3)


def main():
    parser = argparse.ArgumentParser(description='CycloneDX BOM Generator')
    parser.add_argument('-i', action='store', dest='input_file', default='manifest.xlsx')
    parser.add_argument('-o', action='store', dest='output_file', default='export')
    parser.add_argument('-it', action='store', dest='input_type', default='csv')
    parser.add_argument('-ot', action='store', dest='output_type', default='csv')
    parser.add_argument('-n', action='store', dest='input_name', default='unknown')
    parser.add_argument('-v', action='store', dest='component_version', default='unknown')

    args = parser.parse_args()
    print('Input file: ' + args.input_file)
    print('Output BOM: ' + args.output_file)
    print('Input Type: ' + args.input_type)
    print('Output Type: ' + args.output_type)
    print('SBOM Component Name: ' + args.input_name)
    print('SBOM Component Version: ' + args.component_version)

    # buildroot_csv_manifest_to_component(args.input_file)
    create_json_from_sbom(args)


main()
