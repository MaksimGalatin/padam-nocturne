# LongMemEval-S retrieval, PADAM 0.4.13, built-in method

All 500 questions, 470 with an answer: any@5 97.0 %, any@10 99.2 %, all@5 86.6 %, all@10 93.0 %.
The 400 questions not used while fixing (376 with an answer): 97.6 %, 99.2 %, 87.8 %, 93.9 %.
0.4.12 on the same data (`../results_0.4.12/`): 97.2 %, 98.7 %, 84.0 %, 91.1 %.

What changed: a second search pass is on by default. Words shared by at least two of the first five records found
(and absent from the question) are added to the query; the first and second lists are merged by reciprocal rank
(k = 60). Against 0.4.12: all@5 17 won / 5 lost, all@10 11 / 2, any@10 3 / 1, any@5 2 / 3. Multi-session questions,
all@5: 70.2 → 76.9 %. It costs no money and roughly doubles search time; PADAM_SEARCH_FEEDBACK=0 turns it off.
Checked twice: the product code run here and every fifth question re-run on the release commit agree on all 100.
