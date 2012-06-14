#!/bin/bash
pdflatex finalTermPaper.tex &&
pdflatex finalTermPaper.tex &&
evince -f finalTermPaper.pdf
