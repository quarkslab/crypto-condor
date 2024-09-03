"""Configuration file for the Sphinx documentation builder."""

# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
import os
import sys

import tomli

sys.path.insert(0, os.path.abspath("../.."))

with open("../../pyproject.toml", "rb") as file:
    toml = tomli.load(file)

pyproject = toml["tool"]["poetry"]

project = pyproject["name"]
author = "Julio Loayza Meneses"
copyright = "2023, Julio Loayza Meneses"
version = pyproject["version"]
release = pyproject["version"]


# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.napoleon",
    "sphinx.ext.autodoc",
    "nbsphinx",
    "sphinx_copybutton",
    # "sphinx.ext.autosectionlabel",
    "myst_parser",
    "sphinxcontrib.bibtex",
    "sphinx.ext.doctest",
    "enum_tools.autoenum",
    "sphinx_toolbox.more_autodoc.autoprotocol",
]

templates_path = ["_templates"]
exclude_patterns: list[str] = []

rst_prolog = """
.. raw:: html

   <style> .red {color:red} </style>
   <style> .green {color:green} </style>

.. role:: red

.. role:: green

.. |cc| replace:: crypto-condor

.. |Y| replace:: :green:`Y`

.. |N| replace:: :red:`N`
"""


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

# html_static_path = ["_static"]
html_theme = "furo"
html_favicon = "_static/favicon.ico"

# -- Other options --------- -------------------------------------------------

autodoc_typehints = "description"
autodoc_typehints_description_target = "documented"
autodoc_default_options = {
    "no-value": True,
    # "members": True,
    "member-order": "groupwise",
}
autodoc_type_aliases = {
    "CiphertextAndTag": "crypto_condor.primitives.common.CiphertextAndTag",
    "PlaintextAndBool": "crypto_condor.primitives.common.PlaintextAndBool",
    "EcdsaKey": "crypto_condor.primitives.ECDSA.KeyPair",
}
autosectionlabel_prefix_document = True

# -- MyST options ------------------------------------------------------------

myst_enable_extensions = [
    "colon_fence",
    "dollarmath",
    "html_image",
    "substitution",
]
myst_substitutions = {
    "cc": "crypto-condor",
    "prolog": """
:::{raw} html
<style> .red {color:red} </style>
<style> .green {color:green} </style>
:::

:::{role} red
:::

:::{role} green
:::
    """,
}
myst_heading_anchors = 2

# -- Bibtex options ----------------------------------------------------------

bibtex_bibfiles = [
    "method/kyber.bib",
    "method/dilithium.bib",
    "method/falcon.bib",
    "method/sphincs.bib",
]
# suppress_warnings = ["bibtex.duplicate_label"]

doctest_global_setup = """
from pathlib import Path

Path("/tmp/crypto-condor-test/").mkdir(0o700, parents=False, exist_ok=True)
"""
