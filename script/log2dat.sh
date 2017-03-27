#/bin/bash

grep elapsed $@ | sed -e 's/t: //' -e 's/ us, elapsed://' -e 's/ us//'
