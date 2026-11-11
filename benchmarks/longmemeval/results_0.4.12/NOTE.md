# LongMemEval-S retrieval, PADAM 0.4.12, built-in method

All 500 questions, 470 with an answer: any@5 97.2 %, any@10 98.7 %, all@5 84.0 %, all@10 91.1 %.
The 400 questions not used while fixing (every question except each fifth; 376 with an answer): 97.3 %, 98.9 %, 84.6 %, 92.3 %.
0.4.6–0.4.11 on the same data (`../results_0.4.6/`): 96.8 %, 98.7 %, 83.0 %, 90.9 %.

What changed: function words (what, did, the, my, что, как…) are no longer sent to the full-text query. They match almost
every record, so BM25 was computed over the whole store and they diluted the rare words. Against 0.4.11 on the 470
questions: any@5 3 won / 1 lost, all@5 10 won / 5 lost, any@10 3 / 3; on the 376 questions not used while fixing it is
better on all four measures. Median search over 10,000 records with LongMemEval questions: 46.4 → 24.6 ms.
Checked twice: a side-by-side script on one filled store per question, then this run of the product code — the
two agree on every one of the 500 questions.
