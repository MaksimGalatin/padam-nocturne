# LongMemEval-S retrieval, PADAM 0.4.4, built-in method

All 500 questions, 470 with an answer: any@5 91.7 %, any@10 96.4 %, all@5 74.7 %, all@10 85.1 %.

Retrieval is deterministic in this release: ties between records with equal scores keep the order in which the records were stored. An independent run of every fifth question gave the same result on all 100 of them (`retrieval_recall.py` run twice, compared question by question).

`summary.json` and `per_question.json` are that deterministic run. The files ending in `_before_tie_fix` are an earlier run of the same release candidate before the tie fix, when ties fell by a random id; they are kept for comparison and are not the published numbers.
