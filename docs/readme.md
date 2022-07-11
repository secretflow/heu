# Basis


## Install dependencies

```shell
pip install -r requirements.txt
```

## Generate html

```shell
make html
```


# Internationalization

detail doc：
https://www.sphinx-doc.org/en/master/usage/advanced/intl.html

```shell
# generate/update pot files
make gettext

# update po files
sphinx-intl update -p _build/gettext

# <--- Long term work: Add translated text in po file --->

# generate html (en)
sphinx-build -D language='en' . _build/html/en/
```
