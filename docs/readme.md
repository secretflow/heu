# Basis 基本操作

## Install dependencies 安装依赖

```shell
pip install -r requirements.txt
```

## Generate html 生成 html 文档

```shell
make html
```

Now you can open the _build/html/index.html file in your browser to read the HEU
documentation.
现在您可以通过浏览器打开 _build/html/index.html 文件阅读 HEU 文档。


# Internationalization 国际化（可选）

This section describes how to translate documentation into other languages
本节介绍如何将文档翻译为另一种语言

sphinx detail doc：
https://www.sphinx-doc.org/en/master/usage/advanced/intl.html

```shell
# generate/update pot files
make gettext

# generate/update po files
# (merge pot to exist po files or create new po files if not exist)
sphinx-intl update -p _build/gettext

# <--- Long term work: Add translated text in po file --->

# generate html (en)
sphinx-build -D language='en' . _build/html/en/
```
