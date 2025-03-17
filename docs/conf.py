# Copyright 2024 Ant Group Co., Ltd.
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

# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys

sys.path.insert(0, os.path.abspath('../bazel-bin/heu/pybind'))

# -- Project information -----------------------------------------------------

project = 'HEU'
copyright = '2022-2024 Ant Group Co., Ltd'
author = 'HEU authors'

# The full version, including alpha/beta/rc tags
# release = '0.0.6'

# -- Multi-language config ---------------------------------------------------

# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
#
# This is also used if you do content translation via gettext catalogs.
# Usually you set "language" from the command line for these cases.
language = 'zh_CN'
autoclass_content='both'

locale_dirs = ['locale/']
gettext_compact = False  # optional.
gettext_uuid = False  # optional.
# gettext_location = False

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.intersphinx',
    'sphinx.ext.mathjax',
    'sphinx.ext.napoleon',
    "sphinx_inline_tabs",
    "sphinx_togglebutton",
    # "myst_parser",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------

html_favicon = '_static/favicon.ico'

html_css_files = [
    'css/custom.css',
]

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "pydata_sphinx_theme"

html_context = {"default_mode": "light"}

html_sidebars = {"index": [], "**": ["search-field", "sidebar-nav-bs"]}

html_theme_options = {
    "logo": {
        "text": "HEU",
    },
    "pygment_light_style": "tango",
    "pygment_dark_style": "native",
    "icon_links": [
        {
            "name": "GitHub",
            "url": "https://github.com/secretflow/heu",
            "icon": "fa-brands fa-github",
            "type": "fontawesome",
        },
    ],
    # https://pydata-sphinx-theme.readthedocs.io/en/stable/user_guide/layout.html
    # the default "navbar-logo" section is redundant and has bugs, so remove it.
    # "navbar_start": [],
    "secondary_sidebar_items": ["page-toc"],
    # "language_switch_button": True,
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']
