# LongMemEval-S retrieval, PADAM 0.4.6, built-in method

All 500 questions, 470 with an answer: any@5 96.8 %, any@10 98.7 %, all@5 83.0 %, all@10 90.9 %.
The 400 questions not used while fixing (every question except each fifth): 96.5 %, 98.7 %, 83.2 %, 92.0 %.
Plain BM25 with no PADAM on the same rounds (`../baselines/results_bm25/`): 96.0 %, 97.7 %, 79.8 %, 88.5 %.

What changed from 0.4.5 (91.7 %, 96.4 %, 74.7 %, 85.1 %): identifiers are only real identifiers (a case-insensitive
flag made every word of two letters an "identifier"), the built-in vector no longer votes in the fusion (it is the
fallback when no word matches), and the word search matches stems. The variants were compared on every fifth question
first; the final code was then run on all 500, and every fifth question re-run separately agreed on all 100.
