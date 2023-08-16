PUML_FILES=$(wildcard *.puml)
PDF_FILES=$(patsubst %.puml,%.pdf,$(PUML_FILES))

all: $(PDF_FILES)

%.pdf: %.puml
	plantuml -Tpdf $<

clean:
	rm -f *~ *.png *.pdf
