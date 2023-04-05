.. image:: https://img.shields.io/badge/license-Apache%202.0-brightgreen
   :alt: License
   :target: https://github.com/alvinchchen/cyclonedx-buildroot/blob/master/LICENSE

CycloneDX-buildroot Python Module
=======================

The CycloneDX-buildroot module for Python creates a valid CycloneDX bill-of-material document from buildroot manifest.xlsx file.

Usage
-----

**Options**

By default, the buildroot manifest will be read from the current working directory and the resulting output SBOM will
be created in the current working directory. These options can be overwritten as follows:

.. code-block:: console


    $ python3 -m cyclonedxbuildroot.cli.generateBom -it buildroot -i <path>/manifest.csv -ot console -n "My Project" -v "1.2.3.4"
      Usage:  generateBom.cli [OPTIONS]
      Options:
        -i <path> - the alternate filename to a frozen manifest.csv
        -o <path> - the bom file to create
        -it input type indicating expected input format <buildroot | csv>
        -ot output type indicating output destination <console | csv>
        -n name of the project or product SBOM <project name in quotes>
        -v your product SBOM version <project version in quotes>


License
-------

Permission to modify and redistribute is granted under the terms of the Apache 2.0 license.
