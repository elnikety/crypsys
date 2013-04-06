TARG=report.pdf
PARTS=\
	report.tex\
	introduction.tex\
	background.tex\
	protocol.tex\
	implementation.tex\
	refs.bib\
	contributions.tex\

.PHONY: all clean

all:	$(TARG)

clean:
	rm -f *.aux *.log *.bbc *.bbl *.blg *.dvi *.toc *.lot *.lof *.out $(TARG)

%.pdf:	%.tex
	pdflatex $*
	bibtex8 $*
	pdflatex $*
	pdflatex $*

$(TARG): $(PARTS)
