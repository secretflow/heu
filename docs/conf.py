# Copyright 2025 Ant Group Co., Ltd.
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

import sys
from pathlib import Path

# https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html#ensuring-the-code-can-be-imported
sys.path.insert(0, str(Path(__file__).parent.joinpath("../bazel-bin/heu/pylib")))

project = "HEU"

extensions = [
    "secretflow_doctools",
    # API docs
    # https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html
    "sphinx.ext.autodoc",
    # link to titles using :ref:`Title text`
    # https://www.sphinx-doc.org/en/master/usage/extensions/autosectionlabel.html
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.extlinks",
    "sphinx.ext.graphviz",
    # link to other Python projects
    # https://www.sphinx-doc.org/en/master/usage/extensions/intersphinx.html
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
]

# also link to titles using :ref:`path/to/document:Title text`
# (note that path should not have a leading slash)
# https://www.sphinx-doc.org/en/master/usage/extensions/autosectionlabel.html#confval-autosectionlabel_prefix_document
autosectionlabel_prefix_document = True

# source files are in this language
language = "zh_CN"
# translation files are in this directory
locale_dirs = ["./locale/"]
# this should be false so 1 doc file corresponds to 1 translation file
gettext_compact = False
gettext_uuid = False
# allow source texts to keep using outdated translations if they are only marginally changed
# otherwise any change to source text will cause their translations to not appear
gettext_allow_fuzzy_translations = True

# list of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = [
    "CONTRIBUTING.md",  # prevent CONTRIBUTING.md from being included in output, optional
    ".venv",
    "_build",
    "Thumbs.db",
    ".DS_Store",
]

autoclass_content = 'both'
