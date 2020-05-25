.. image:: https://img.shields.io/badge/license-Apache%202.0-brightgreen
   :alt: License
   :target: https://github.com/alvinchchen/cyclonedx-buildroot/blob/master/LICENSE

CycloneDX-buildroot Python Module
=======================

The CycloneDX-buildroot module for Python creates a valid CycloneDX bill-of-material document from buildroot manifest.xlsx file.

Usage
-----

**Options**

By default, manifest.xslx will be read from the current working directory and the resulting bom.xml will also
be created in the current working directory. These options can be overwritten as follows:

.. code-block:: console

    $ python3 -m cyclonedxbuildroot.cli.generateBom -i manifest.csv
      Usage:  cyclonedx-py [OPTIONS]
      Options:
        -i <path> - the alternate filename to a frozen manifest.csv
        -o <path> - the bom file to create


License
-------

Permission to modify and redistribute is granted under the terms of the Apache 2.0 license.
