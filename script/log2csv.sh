#/bin/bash

echo "t(us),elapsed(us),req_id,thr_id,sess_id"
grep elapsed $@ | sed -e 's/t: //' -e 's/ us, elapsed: /,/' -e 's/ us, req_id: /,/' -e 's/, thr_id: /,/' -e 's/, sess_id: /,/' -e 's/ us//'
