# tunables before decompile
  $ crushtool -d "$TESTDIR/simple.template" --set-straw-calc-version 1 | head -2
  # begin crush map
  tunable straw_calc_version 1
# build then reweight-item then tree
  $ map="$TESTDIR/foo"
  $ crushtool --outfn "$map" --build --set-chooseleaf-vary-r 0 --set-chooseleaf-stable 0 --num_osds 25 node straw 5 rack straw 1 root straw 0 --reweight-item osd.2 99 -o "$map" --tree
  crushtool reweighting item osd.2 to 99
  ID\tWEIGHT\tTYPE NAME (esc)
  -11\t123.00000\troot root (esc)
  -6\t103.00000\t\track rack0 (esc)
  -1\t103.00000\t\t\tnode node0 (esc)
  0\t1.00000\t\t\t\tosd.0 (esc)
  1\t1.00000\t\t\t\tosd.1 (esc)
  2\t99.00000\t\t\t\tosd.2 (esc)
  3\t1.00000\t\t\t\tosd.3 (esc)
  4\t1.00000\t\t\t\tosd.4 (esc)
  -7\t5.00000\t\track rack1 (esc)
  -2\t5.00000\t\t\tnode node1 (esc)
  5\t1.00000\t\t\t\tosd.5 (esc)
  6\t1.00000\t\t\t\tosd.6 (esc)
  7\t1.00000\t\t\t\tosd.7 (esc)
  8\t1.00000\t\t\t\tosd.8 (esc)
  9\t1.00000\t\t\t\tosd.9 (esc)
  -8\t5.00000\t\track rack2 (esc)
  -3\t5.00000\t\t\tnode node2 (esc)
  10\t1.00000\t\t\t\tosd.10 (esc)
  11\t1.00000\t\t\t\tosd.11 (esc)
  12\t1.00000\t\t\t\tosd.12 (esc)
  13\t1.00000\t\t\t\tosd.13 (esc)
  14\t1.00000\t\t\t\tosd.14 (esc)
  -9\t5.00000\t\track rack3 (esc)
  -4\t5.00000\t\t\tnode node3 (esc)
  15\t1.00000\t\t\t\tosd.15 (esc)
  16\t1.00000\t\t\t\tosd.16 (esc)
  17\t1.00000\t\t\t\tosd.17 (esc)
  18\t1.00000\t\t\t\tosd.18 (esc)
  19\t1.00000\t\t\t\tosd.19 (esc)
  -10\t5.00000\t\track rack4 (esc)
  -5\t5.00000\t\t\tnode node4 (esc)
  20\t1.00000\t\t\t\tosd.20 (esc)
  21\t1.00000\t\t\t\tosd.21 (esc)
  22\t1.00000\t\t\t\tosd.22 (esc)
  23\t1.00000\t\t\t\tosd.23 (esc)
  24\t1.00000\t\t\t\tosd.24 (esc)
  $ crushtool -d "$map"
  # begin crush map
  tunable choose_local_tries 0
  tunable choose_local_fallback_tries 0
  tunable choose_total_tries 50
  tunable chooseleaf_descend_once 1
  tunable straw_calc_version 1
  tunable allowed_bucket_algs 54
  
  # devices
  device 0 osd.0
  device 1 osd.1
  device 2 osd.2
  device 3 osd.3
  device 4 osd.4
  device 5 osd.5
  device 6 osd.6
  device 7 osd.7
  device 8 osd.8
  device 9 osd.9
  device 10 osd.10
  device 11 osd.11
  device 12 osd.12
  device 13 osd.13
  device 14 osd.14
  device 15 osd.15
  device 16 osd.16
  device 17 osd.17
  device 18 osd.18
  device 19 osd.19
  device 20 osd.20
  device 21 osd.21
  device 22 osd.22
  device 23 osd.23
  device 24 osd.24
  
  # types
  type 0 osd
  type 1 node
  type 2 rack
  type 3 root
  
  # buckets
  node node0 {
  \tid -1\t\t# do not change unnecessarily (esc)
  \t# weight 103.000 (esc)
  \talg straw (esc)
  \thash 0\t# rjenkins1 (esc)
  \titem osd.0 weight 1.000 (esc)
  \titem osd.1 weight 1.000 (esc)
  \titem osd.2 weight 99.000 (esc)
  \titem osd.3 weight 1.000 (esc)
  \titem osd.4 weight 1.000 (esc)
  }
  node node1 {
  \tid -2\t\t# do not change unnecessarily (esc)
  \t# weight 5.000 (esc)
  \talg straw (esc)
  \thash 0\t# rjenkins1 (esc)
  \titem osd.5 weight 1.000 (esc)
  \titem osd.6 weight 1.000 (esc)
  \titem osd.7 weight 1.000 (esc)
  \titem osd.8 weight 1.000 (esc)
  \titem osd.9 weight 1.000 (esc)
  }
  node node2 {
  \tid -3\t\t# do not change unnecessarily (esc)
  \t# weight 5.000 (esc)
  \talg straw (esc)
  \thash 0\t# rjenkins1 (esc)
  \titem osd.10 weight 1.000 (esc)
  \titem osd.11 weight 1.000 (esc)
  \titem osd.12 weight 1.000 (esc)
  \titem osd.13 weight 1.000 (esc)
  \titem osd.14 weight 1.000 (esc)
  }
  node node3 {
  \tid -4\t\t# do not change unnecessarily (esc)
  \t# weight 5.000 (esc)
  \talg straw (esc)
  \thash 0\t# rjenkins1 (esc)
  \titem osd.15 weight 1.000 (esc)
  \titem osd.16 weight 1.000 (esc)
  \titem osd.17 weight 1.000 (esc)
  \titem osd.18 weight 1.000 (esc)
  \titem osd.19 weight 1.000 (esc)
  }
  node node4 {
  \tid -5\t\t# do not change unnecessarily (esc)
  \t# weight 5.000 (esc)
  \talg straw (esc)
  \thash 0\t# rjenkins1 (esc)
  \titem osd.20 weight 1.000 (esc)
  \titem osd.21 weight 1.000 (esc)
  \titem osd.22 weight 1.000 (esc)
  \titem osd.23 weight 1.000 (esc)
  \titem osd.24 weight 1.000 (esc)
  }
  rack rack0 {
  \tid -6\t\t# do not change unnecessarily (esc)
  \t# weight 103.000 (esc)
  \talg straw (esc)
  \thash 0\t# rjenkins1 (esc)
  \titem node0 weight 103.000 (esc)
  }
  rack rack1 {
  \tid -7\t\t# do not change unnecessarily (esc)
  \t# weight 5.000 (esc)
  \talg straw (esc)
  \thash 0\t# rjenkins1 (esc)
  \titem node1 weight 5.000 (esc)
  }
  rack rack2 {
  \tid -8\t\t# do not change unnecessarily (esc)
  \t# weight 5.000 (esc)
  \talg straw (esc)
  \thash 0\t# rjenkins1 (esc)
  \titem node2 weight 5.000 (esc)
  }
  rack rack3 {
  \tid -9\t\t# do not change unnecessarily (esc)
  \t# weight 5.000 (esc)
  \talg straw (esc)
  \thash 0\t# rjenkins1 (esc)
  \titem node3 weight 5.000 (esc)
  }
  rack rack4 {
  \tid -10\t\t# do not change unnecessarily (esc)
  \t# weight 5.000 (esc)
  \talg straw (esc)
  \thash 0\t# rjenkins1 (esc)
  \titem node4 weight 5.000 (esc)
  }
  root root {
  \tid -11\t\t# do not change unnecessarily (esc)
  \t# weight 123.000 (esc)
  \talg straw (esc)
  \thash 0\t# rjenkins1 (esc)
  \titem rack0 weight 103.000 (esc)
  \titem rack1 weight 5.000 (esc)
  \titem rack2 weight 5.000 (esc)
  \titem rack3 weight 5.000 (esc)
  \titem rack4 weight 5.000 (esc)
  }
  
  # rules
  rule replicated_ruleset {
  \truleset 0 (esc)
  \ttype replicated (esc)
  \tmin_size 1 (esc)
  \tmax_size 10 (esc)
  \tstep take root (esc)
  \tstep chooseleaf firstn 0 type node (esc)
  \tstep emit (esc)
  }
  
  # end crush map
# tunables before reweight
  $ crushtool -i "$map" --set-straw-calc-version 0 --reweight --test --show-utilization --max-x 100 --min-x 1
  rule 0 (replicated_ruleset), x = 1..100, numrep = 1..10
  rule 0 (replicated_ruleset) num_rep 1 result size == 1:\t100/100 (esc)
    device 0:\t\t stored : 4\t expected : 4 (esc)
    device 1:\t\t stored : 4\t expected : 4 (esc)
    device 2:\t\t stored : 40\t expected : 4 (esc)
    device 3:\t\t stored : 6\t expected : 4 (esc)
    device 4:\t\t stored : 1\t expected : 4 (esc)
    device 5:\t\t stored : 2\t expected : 4 (esc)
    device 7:\t\t stored : 2\t expected : 4 (esc)
    device 8:\t\t stored : 3\t expected : 4 (esc)
    device 9:\t\t stored : 4\t expected : 4 (esc)
    device 12:\t\t stored : 2\t expected : 4 (esc)
    device 13:\t\t stored : 1\t expected : 4 (esc)
    device 14:\t\t stored : 4\t expected : 4 (esc)
    device 15:\t\t stored : 2\t expected : 4 (esc)
    device 16:\t\t stored : 5\t expected : 4 (esc)
    device 17:\t\t stored : 3\t expected : 4 (esc)
    device 19:\t\t stored : 5\t expected : 4 (esc)
    device 20:\t\t stored : 5\t expected : 4 (esc)
    device 21:\t\t stored : 1\t expected : 4 (esc)
    device 22:\t\t stored : 2\t expected : 4 (esc)
    device 23:\t\t stored : 2\t expected : 4 (esc)
    device 24:\t\t stored : 2\t expected : 4 (esc)
  rule 0 (replicated_ruleset) num_rep 2 result size == 2:\t100/100 (esc)
    device 0:\t\t stored : 6\t expected : 8 (esc)
    device 1:\t\t stored : 6\t expected : 8 (esc)
    device 2:\t\t stored : 60\t expected : 8 (esc)
    device 3:\t\t stored : 6\t expected : 8 (esc)
    device 4:\t\t stored : 6\t expected : 8 (esc)
    device 5:\t\t stored : 4\t expected : 8 (esc)
    device 6:\t\t stored : 2\t expected : 8 (esc)
    device 7:\t\t stored : 4\t expected : 8 (esc)
    device 8:\t\t stored : 5\t expected : 8 (esc)
    device 9:\t\t stored : 10\t expected : 8 (esc)
    device 10:\t\t stored : 3\t expected : 8 (esc)
    device 11:\t\t stored : 5\t expected : 8 (esc)
    device 12:\t\t stored : 6\t expected : 8 (esc)
    device 13:\t\t stored : 3\t expected : 8 (esc)
    device 14:\t\t stored : 7\t expected : 8 (esc)
    device 15:\t\t stored : 8\t expected : 8 (esc)
    device 16:\t\t stored : 7\t expected : 8 (esc)
    device 17:\t\t stored : 7\t expected : 8 (esc)
    device 18:\t\t stored : 6\t expected : 8 (esc)
    device 19:\t\t stored : 11\t expected : 8 (esc)
    device 20:\t\t stored : 12\t expected : 8 (esc)
    device 21:\t\t stored : 1\t expected : 8 (esc)
    device 22:\t\t stored : 4\t expected : 8 (esc)
    device 23:\t\t stored : 5\t expected : 8 (esc)
    device 24:\t\t stored : 6\t expected : 8 (esc)
  rule 0 (replicated_ruleset) num_rep 3 result size == 3:\t100/100 (esc)
    device 0:\t\t stored : 8\t expected : 12 (esc)
    device 1:\t\t stored : 6\t expected : 12 (esc)
    device 2:\t\t stored : 69\t expected : 12 (esc)
    device 3:\t\t stored : 6\t expected : 12 (esc)
    device 4:\t\t stored : 6\t expected : 12 (esc)
    device 5:\t\t stored : 8\t expected : 12 (esc)
    device 6:\t\t stored : 9\t expected : 12 (esc)
    device 7:\t\t stored : 7\t expected : 12 (esc)
    device 8:\t\t stored : 14\t expected : 12 (esc)
    device 9:\t\t stored : 16\t expected : 12 (esc)
    device 10:\t\t stored : 6\t expected : 12 (esc)
    device 11:\t\t stored : 11\t expected : 12 (esc)
    device 12:\t\t stored : 9\t expected : 12 (esc)
    device 13:\t\t stored : 8\t expected : 12 (esc)
    device 14:\t\t stored : 7\t expected : 12 (esc)
    device 15:\t\t stored : 8\t expected : 12 (esc)
    device 16:\t\t stored : 9\t expected : 12 (esc)
    device 17:\t\t stored : 11\t expected : 12 (esc)
    device 18:\t\t stored : 9\t expected : 12 (esc)
    device 19:\t\t stored : 16\t expected : 12 (esc)
    device 20:\t\t stored : 18\t expected : 12 (esc)
    device 21:\t\t stored : 5\t expected : 12 (esc)
    device 22:\t\t stored : 15\t expected : 12 (esc)
    device 23:\t\t stored : 8\t expected : 12 (esc)
    device 24:\t\t stored : 11\t expected : 12 (esc)
  rule 0 (replicated_ruleset) num_rep 4 result size == 4:\t100/100 (esc)
    device 0:\t\t stored : 8\t expected : 16 (esc)
    device 1:\t\t stored : 6\t expected : 16 (esc)
    device 2:\t\t stored : 72\t expected : 16 (esc)
    device 3:\t\t stored : 6\t expected : 16 (esc)
    device 4:\t\t stored : 6\t expected : 16 (esc)
    device 5:\t\t stored : 13\t expected : 16 (esc)
    device 6:\t\t stored : 13\t expected : 16 (esc)
    device 7:\t\t stored : 13\t expected : 16 (esc)
    device 8:\t\t stored : 15\t expected : 16 (esc)
    device 9:\t\t stored : 20\t expected : 16 (esc)
    device 10:\t\t stored : 11\t expected : 16 (esc)
    device 11:\t\t stored : 20\t expected : 16 (esc)
    device 12:\t\t stored : 13\t expected : 16 (esc)
    device 13:\t\t stored : 13\t expected : 16 (esc)
    device 14:\t\t stored : 11\t expected : 16 (esc)
    device 15:\t\t stored : 19\t expected : 16 (esc)
    device 16:\t\t stored : 12\t expected : 16 (esc)
    device 17:\t\t stored : 13\t expected : 16 (esc)
    device 18:\t\t stored : 17\t expected : 16 (esc)
    device 19:\t\t stored : 22\t expected : 16 (esc)
    device 20:\t\t stored : 21\t expected : 16 (esc)
    device 21:\t\t stored : 11\t expected : 16 (esc)
    device 22:\t\t stored : 20\t expected : 16 (esc)
    device 23:\t\t stored : 10\t expected : 16 (esc)
    device 24:\t\t stored : 15\t expected : 16 (esc)
  rule 0 (replicated_ruleset) num_rep 5 result size == 4:\t3/100 (esc)
  rule 0 (replicated_ruleset) num_rep 5 result size == 5:\t97/100 (esc)
    device 0:\t\t stored : 8\t expected : 20 (esc)
    device 1:\t\t stored : 6\t expected : 20 (esc)
    device 2:\t\t stored : 74\t expected : 20 (esc)
    device 3:\t\t stored : 6\t expected : 20 (esc)
    device 4:\t\t stored : 6\t expected : 20 (esc)
    device 5:\t\t stored : 17\t expected : 20 (esc)
    device 6:\t\t stored : 17\t expected : 20 (esc)
    device 7:\t\t stored : 19\t expected : 20 (esc)
    device 8:\t\t stored : 18\t expected : 20 (esc)
    device 9:\t\t stored : 27\t expected : 20 (esc)
    device 10:\t\t stored : 15\t expected : 20 (esc)
    device 11:\t\t stored : 28\t expected : 20 (esc)
    device 12:\t\t stored : 22\t expected : 20 (esc)
    device 13:\t\t stored : 18\t expected : 20 (esc)
    device 14:\t\t stored : 17\t expected : 20 (esc)
    device 15:\t\t stored : 22\t expected : 20 (esc)
    device 16:\t\t stored : 14\t expected : 20 (esc)
    device 17:\t\t stored : 19\t expected : 20 (esc)
    device 18:\t\t stored : 20\t expected : 20 (esc)
    device 19:\t\t stored : 25\t expected : 20 (esc)
    device 20:\t\t stored : 24\t expected : 20 (esc)
    device 21:\t\t stored : 19\t expected : 20 (esc)
    device 22:\t\t stored : 25\t expected : 20 (esc)
    device 23:\t\t stored : 13\t expected : 20 (esc)
    device 24:\t\t stored : 18\t expected : 20 (esc)
  rule 0 (replicated_ruleset) num_rep 6 result size == 4:\t3/100 (esc)
  rule 0 (replicated_ruleset) num_rep 6 result size == 5:\t97/100 (esc)
    device 0:\t\t stored : 8\t expected : 20 (esc)
    device 1:\t\t stored : 6\t expected : 20 (esc)
    device 2:\t\t stored : 74\t expected : 20 (esc)
    device 3:\t\t stored : 6\t expected : 20 (esc)
    device 4:\t\t stored : 6\t expected : 20 (esc)
    device 5:\t\t stored : 17\t expected : 20 (esc)
    device 6:\t\t stored : 17\t expected : 20 (esc)
    device 7:\t\t stored : 19\t expected : 20 (esc)
    device 8:\t\t stored : 18\t expected : 20 (esc)
    device 9:\t\t stored : 27\t expected : 20 (esc)
    device 10:\t\t stored : 15\t expected : 20 (esc)
    device 11:\t\t stored : 28\t expected : 20 (esc)
    device 12:\t\t stored : 22\t expected : 20 (esc)
    device 13:\t\t stored : 18\t expected : 20 (esc)
    device 14:\t\t stored : 17\t expected : 20 (esc)
    device 15:\t\t stored : 22\t expected : 20 (esc)
    device 16:\t\t stored : 14\t expected : 20 (esc)
    device 17:\t\t stored : 19\t expected : 20 (esc)
    device 18:\t\t stored : 20\t expected : 20 (esc)
    device 19:\t\t stored : 25\t expected : 20 (esc)
    device 20:\t\t stored : 24\t expected : 20 (esc)
    device 21:\t\t stored : 19\t expected : 20 (esc)
    device 22:\t\t stored : 25\t expected : 20 (esc)
    device 23:\t\t stored : 13\t expected : 20 (esc)
    device 24:\t\t stored : 18\t expected : 20 (esc)
  rule 0 (replicated_ruleset) num_rep 7 result size == 4:\t3/100 (esc)
  rule 0 (replicated_ruleset) num_rep 7 result size == 5:\t97/100 (esc)
    device 0:\t\t stored : 8\t expected : 20 (esc)
    device 1:\t\t stored : 6\t expected : 20 (esc)
    device 2:\t\t stored : 74\t expected : 20 (esc)
    device 3:\t\t stored : 6\t expected : 20 (esc)
    device 4:\t\t stored : 6\t expected : 20 (esc)
    device 5:\t\t stored : 17\t expected : 20 (esc)
    device 6:\t\t stored : 17\t expected : 20 (esc)
    device 7:\t\t stored : 19\t expected : 20 (esc)
    device 8:\t\t stored : 18\t expected : 20 (esc)
    device 9:\t\t stored : 27\t expected : 20 (esc)
    device 10:\t\t stored : 15\t expected : 20 (esc)
    device 11:\t\t stored : 28\t expected : 20 (esc)
    device 12:\t\t stored : 22\t expected : 20 (esc)
    device 13:\t\t stored : 18\t expected : 20 (esc)
    device 14:\t\t stored : 17\t expected : 20 (esc)
    device 15:\t\t stored : 22\t expected : 20 (esc)
    device 16:\t\t stored : 14\t expected : 20 (esc)
    device 17:\t\t stored : 19\t expected : 20 (esc)
    device 18:\t\t stored : 20\t expected : 20 (esc)
    device 19:\t\t stored : 25\t expected : 20 (esc)
    device 20:\t\t stored : 24\t expected : 20 (esc)
    device 21:\t\t stored : 19\t expected : 20 (esc)
    device 22:\t\t stored : 25\t expected : 20 (esc)
    device 23:\t\t stored : 13\t expected : 20 (esc)
    device 24:\t\t stored : 18\t expected : 20 (esc)
  rule 0 (replicated_ruleset) num_rep 8 result size == 4:\t3/100 (esc)
  rule 0 (replicated_ruleset) num_rep 8 result size == 5:\t97/100 (esc)
    device 0:\t\t stored : 8\t expected : 20 (esc)
    device 1:\t\t stored : 6\t expected : 20 (esc)
    device 2:\t\t stored : 74\t expected : 20 (esc)
    device 3:\t\t stored : 6\t expected : 20 (esc)
    device 4:\t\t stored : 6\t expected : 20 (esc)
    device 5:\t\t stored : 17\t expected : 20 (esc)
    device 6:\t\t stored : 17\t expected : 20 (esc)
    device 7:\t\t stored : 19\t expected : 20 (esc)
    device 8:\t\t stored : 18\t expected : 20 (esc)
    device 9:\t\t stored : 27\t expected : 20 (esc)
    device 10:\t\t stored : 15\t expected : 20 (esc)
    device 11:\t\t stored : 28\t expected : 20 (esc)
    device 12:\t\t stored : 22\t expected : 20 (esc)
    device 13:\t\t stored : 18\t expected : 20 (esc)
    device 14:\t\t stored : 17\t expected : 20 (esc)
    device 15:\t\t stored : 22\t expected : 20 (esc)
    device 16:\t\t stored : 14\t expected : 20 (esc)
    device 17:\t\t stored : 19\t expected : 20 (esc)
    device 18:\t\t stored : 20\t expected : 20 (esc)
    device 19:\t\t stored : 25\t expected : 20 (esc)
    device 20:\t\t stored : 24\t expected : 20 (esc)
    device 21:\t\t stored : 19\t expected : 20 (esc)
    device 22:\t\t stored : 25\t expected : 20 (esc)
    device 23:\t\t stored : 13\t expected : 20 (esc)
    device 24:\t\t stored : 18\t expected : 20 (esc)
  rule 0 (replicated_ruleset) num_rep 9 result size == 4:\t2/100 (esc)
  rule 0 (replicated_ruleset) num_rep 9 result size == 5:\t98/100 (esc)
    device 0:\t\t stored : 8\t expected : 20 (esc)
    device 1:\t\t stored : 6\t expected : 20 (esc)
    device 2:\t\t stored : 74\t expected : 20 (esc)
    device 3:\t\t stored : 6\t expected : 20 (esc)
    device 4:\t\t stored : 6\t expected : 20 (esc)
    device 5:\t\t stored : 17\t expected : 20 (esc)
    device 6:\t\t stored : 17\t expected : 20 (esc)
    device 7:\t\t stored : 19\t expected : 20 (esc)
    device 8:\t\t stored : 18\t expected : 20 (esc)
    device 9:\t\t stored : 28\t expected : 20 (esc)
    device 10:\t\t stored : 15\t expected : 20 (esc)
    device 11:\t\t stored : 28\t expected : 20 (esc)
    device 12:\t\t stored : 22\t expected : 20 (esc)
    device 13:\t\t stored : 18\t expected : 20 (esc)
    device 14:\t\t stored : 17\t expected : 20 (esc)
    device 15:\t\t stored : 22\t expected : 20 (esc)
    device 16:\t\t stored : 14\t expected : 20 (esc)
    device 17:\t\t stored : 19\t expected : 20 (esc)
    device 18:\t\t stored : 20\t expected : 20 (esc)
    device 19:\t\t stored : 25\t expected : 20 (esc)
    device 20:\t\t stored : 24\t expected : 20 (esc)
    device 21:\t\t stored : 19\t expected : 20 (esc)
    device 22:\t\t stored : 25\t expected : 20 (esc)
    device 23:\t\t stored : 13\t expected : 20 (esc)
    device 24:\t\t stored : 18\t expected : 20 (esc)
  rule 0 (replicated_ruleset) num_rep 10 result size == 4:\t2/100 (esc)
  rule 0 (replicated_ruleset) num_rep 10 result size == 5:\t98/100 (esc)
    device 0:\t\t stored : 8\t expected : 20 (esc)
    device 1:\t\t stored : 6\t expected : 20 (esc)
    device 2:\t\t stored : 74\t expected : 20 (esc)
    device 3:\t\t stored : 6\t expected : 20 (esc)
    device 4:\t\t stored : 6\t expected : 20 (esc)
    device 5:\t\t stored : 17\t expected : 20 (esc)
    device 6:\t\t stored : 17\t expected : 20 (esc)
    device 7:\t\t stored : 19\t expected : 20 (esc)
    device 8:\t\t stored : 18\t expected : 20 (esc)
    device 9:\t\t stored : 28\t expected : 20 (esc)
    device 10:\t\t stored : 15\t expected : 20 (esc)
    device 11:\t\t stored : 28\t expected : 20 (esc)
    device 12:\t\t stored : 22\t expected : 20 (esc)
    device 13:\t\t stored : 18\t expected : 20 (esc)
    device 14:\t\t stored : 17\t expected : 20 (esc)
    device 15:\t\t stored : 22\t expected : 20 (esc)
    device 16:\t\t stored : 14\t expected : 20 (esc)
    device 17:\t\t stored : 19\t expected : 20 (esc)
    device 18:\t\t stored : 20\t expected : 20 (esc)
    device 19:\t\t stored : 25\t expected : 20 (esc)
    device 20:\t\t stored : 24\t expected : 20 (esc)
    device 21:\t\t stored : 19\t expected : 20 (esc)
    device 22:\t\t stored : 25\t expected : 20 (esc)
    device 23:\t\t stored : 13\t expected : 20 (esc)
    device 24:\t\t stored : 18\t expected : 20 (esc)
  crushtool successfully built or modified map.  Use '-o <file>' to write it out.
  $ crushtool -i "$map" --set-straw-calc-version 1 --reweight --test --show-utilization --max-x 100 --min-x 1
  rule 0 (replicated_ruleset), x = 1..100, numrep = 1..10
  rule 0 (replicated_ruleset) num_rep 1 result size == 1:\t100/100 (esc)
    device 1:\t\t stored : 1\t expected : 4 (esc)
    device 2:\t\t stored : 75\t expected : 4 (esc)
    device 3:\t\t stored : 2\t expected : 4 (esc)
    device 4:\t\t stored : 1\t expected : 4 (esc)
    device 5:\t\t stored : 2\t expected : 4 (esc)
    device 7:\t\t stored : 2\t expected : 4 (esc)
    device 8:\t\t stored : 1\t expected : 4 (esc)
    device 9:\t\t stored : 2\t expected : 4 (esc)
    device 14:\t\t stored : 3\t expected : 4 (esc)
    device 16:\t\t stored : 3\t expected : 4 (esc)
    device 19:\t\t stored : 4\t expected : 4 (esc)
    device 20:\t\t stored : 2\t expected : 4 (esc)
    device 22:\t\t stored : 1\t expected : 4 (esc)
    device 23:\t\t stored : 1\t expected : 4 (esc)
  rule 0 (replicated_ruleset) num_rep 2 result size == 2:\t100/100 (esc)
    device 0:\t\t stored : 1\t expected : 8 (esc)
    device 1:\t\t stored : 1\t expected : 8 (esc)
    device 2:\t\t stored : 95\t expected : 8 (esc)
    device 3:\t\t stored : 2\t expected : 8 (esc)
    device 4:\t\t stored : 1\t expected : 8 (esc)
    device 5:\t\t stored : 3\t expected : 8 (esc)
    device 6:\t\t stored : 3\t expected : 8 (esc)
    device 7:\t\t stored : 7\t expected : 8 (esc)
    device 8:\t\t stored : 4\t expected : 8 (esc)
    device 9:\t\t stored : 8\t expected : 8 (esc)
    device 11:\t\t stored : 1\t expected : 8 (esc)
    device 12:\t\t stored : 4\t expected : 8 (esc)
    device 13:\t\t stored : 2\t expected : 8 (esc)
    device 14:\t\t stored : 6\t expected : 8 (esc)
    device 15:\t\t stored : 5\t expected : 8 (esc)
    device 16:\t\t stored : 4\t expected : 8 (esc)
    device 17:\t\t stored : 8\t expected : 8 (esc)
    device 18:\t\t stored : 5\t expected : 8 (esc)
    device 19:\t\t stored : 9\t expected : 8 (esc)
    device 20:\t\t stored : 7\t expected : 8 (esc)
    device 21:\t\t stored : 5\t expected : 8 (esc)
    device 22:\t\t stored : 6\t expected : 8 (esc)
    device 23:\t\t stored : 5\t expected : 8 (esc)
    device 24:\t\t stored : 8\t expected : 8 (esc)
  rule 0 (replicated_ruleset) num_rep 3 result size == 3:\t100/100 (esc)
    device 0:\t\t stored : 1\t expected : 12 (esc)
    device 1:\t\t stored : 1\t expected : 12 (esc)
    device 2:\t\t stored : 95\t expected : 12 (esc)
    device 3:\t\t stored : 2\t expected : 12 (esc)
    device 4:\t\t stored : 1\t expected : 12 (esc)
    device 5:\t\t stored : 4\t expected : 12 (esc)
    device 6:\t\t stored : 5\t expected : 12 (esc)
    device 7:\t\t stored : 10\t expected : 12 (esc)
    device 8:\t\t stored : 16\t expected : 12 (esc)
    device 9:\t\t stored : 13\t expected : 12 (esc)
    device 10:\t\t stored : 8\t expected : 12 (esc)
    device 11:\t\t stored : 5\t expected : 12 (esc)
    device 12:\t\t stored : 5\t expected : 12 (esc)
    device 13:\t\t stored : 5\t expected : 12 (esc)
    device 14:\t\t stored : 8\t expected : 12 (esc)
    device 15:\t\t stored : 11\t expected : 12 (esc)
    device 16:\t\t stored : 17\t expected : 12 (esc)
    device 17:\t\t stored : 12\t expected : 12 (esc)
    device 18:\t\t stored : 9\t expected : 12 (esc)
    device 19:\t\t stored : 15\t expected : 12 (esc)
    device 20:\t\t stored : 16\t expected : 12 (esc)
    device 21:\t\t stored : 8\t expected : 12 (esc)
    device 22:\t\t stored : 11\t expected : 12 (esc)
    device 23:\t\t stored : 11\t expected : 12 (esc)
    device 24:\t\t stored : 11\t expected : 12 (esc)
  rule 0 (replicated_ruleset) num_rep 4 result size == 3:\t3/100 (esc)
  rule 0 (replicated_ruleset) num_rep 4 result size == 4:\t97/100 (esc)
    device 0:\t\t stored : 1\t expected : 16 (esc)
    device 1:\t\t stored : 1\t expected : 16 (esc)
    device 2:\t\t stored : 95\t expected : 16 (esc)
    device 3:\t\t stored : 2\t expected : 16 (esc)
    device 4:\t\t stored : 1\t expected : 16 (esc)
    device 5:\t\t stored : 11\t expected : 16 (esc)
    device 6:\t\t stored : 12\t expected : 16 (esc)
    device 7:\t\t stored : 16\t expected : 16 (esc)
    device 8:\t\t stored : 19\t expected : 16 (esc)
    device 9:\t\t stored : 18\t expected : 16 (esc)
    device 10:\t\t stored : 12\t expected : 16 (esc)
    device 11:\t\t stored : 12\t expected : 16 (esc)
    device 12:\t\t stored : 13\t expected : 16 (esc)
    device 13:\t\t stored : 11\t expected : 16 (esc)
    device 14:\t\t stored : 16\t expected : 16 (esc)
    device 15:\t\t stored : 19\t expected : 16 (esc)
    device 16:\t\t stored : 19\t expected : 16 (esc)
    device 17:\t\t stored : 15\t expected : 16 (esc)
    device 18:\t\t stored : 11\t expected : 16 (esc)
    device 19:\t\t stored : 18\t expected : 16 (esc)
    device 20:\t\t stored : 22\t expected : 16 (esc)
    device 21:\t\t stored : 12\t expected : 16 (esc)
    device 22:\t\t stored : 14\t expected : 16 (esc)
    device 23:\t\t stored : 13\t expected : 16 (esc)
    device 24:\t\t stored : 14\t expected : 16 (esc)
  rule 0 (replicated_ruleset) num_rep 5 result size == 3:\t3/100 (esc)
  rule 0 (replicated_ruleset) num_rep 5 result size == 4:\t43/100 (esc)
  rule 0 (replicated_ruleset) num_rep 5 result size == 5:\t54/100 (esc)
    device 0:\t\t stored : 1\t expected : 20 (esc)
    device 1:\t\t stored : 1\t expected : 20 (esc)
    device 2:\t\t stored : 95\t expected : 20 (esc)
    device 3:\t\t stored : 2\t expected : 20 (esc)
    device 4:\t\t stored : 1\t expected : 20 (esc)
    device 5:\t\t stored : 14\t expected : 20 (esc)
    device 6:\t\t stored : 14\t expected : 20 (esc)
    device 7:\t\t stored : 16\t expected : 20 (esc)
    device 8:\t\t stored : 19\t expected : 20 (esc)
    device 9:\t\t stored : 22\t expected : 20 (esc)
    device 10:\t\t stored : 15\t expected : 20 (esc)
    device 11:\t\t stored : 16\t expected : 20 (esc)
    device 12:\t\t stored : 17\t expected : 20 (esc)
    device 13:\t\t stored : 18\t expected : 20 (esc)
    device 14:\t\t stored : 19\t expected : 20 (esc)
    device 15:\t\t stored : 19\t expected : 20 (esc)
    device 16:\t\t stored : 20\t expected : 20 (esc)
    device 17:\t\t stored : 17\t expected : 20 (esc)
    device 18:\t\t stored : 15\t expected : 20 (esc)
    device 19:\t\t stored : 20\t expected : 20 (esc)
    device 20:\t\t stored : 26\t expected : 20 (esc)
    device 21:\t\t stored : 17\t expected : 20 (esc)
    device 22:\t\t stored : 16\t expected : 20 (esc)
    device 23:\t\t stored : 15\t expected : 20 (esc)
    device 24:\t\t stored : 16\t expected : 20 (esc)
  rule 0 (replicated_ruleset) num_rep 6 result size == 3:\t2/100 (esc)
  rule 0 (replicated_ruleset) num_rep 6 result size == 4:\t43/100 (esc)
  rule 0 (replicated_ruleset) num_rep 6 result size == 5:\t55/100 (esc)
    device 0:\t\t stored : 1\t expected : 20 (esc)
    device 1:\t\t stored : 1\t expected : 20 (esc)
    device 2:\t\t stored : 95\t expected : 20 (esc)
    device 3:\t\t stored : 2\t expected : 20 (esc)
    device 4:\t\t stored : 1\t expected : 20 (esc)
    device 5:\t\t stored : 14\t expected : 20 (esc)
    device 6:\t\t stored : 14\t expected : 20 (esc)
    device 7:\t\t stored : 16\t expected : 20 (esc)
    device 8:\t\t stored : 19\t expected : 20 (esc)
    device 9:\t\t stored : 22\t expected : 20 (esc)
    device 10:\t\t stored : 15\t expected : 20 (esc)
    device 11:\t\t stored : 16\t expected : 20 (esc)
    device 12:\t\t stored : 17\t expected : 20 (esc)
    device 13:\t\t stored : 18\t expected : 20 (esc)
    device 14:\t\t stored : 20\t expected : 20 (esc)
    device 15:\t\t stored : 19\t expected : 20 (esc)
    device 16:\t\t stored : 20\t expected : 20 (esc)
    device 17:\t\t stored : 17\t expected : 20 (esc)
    device 18:\t\t stored : 15\t expected : 20 (esc)
    device 19:\t\t stored : 20\t expected : 20 (esc)
    device 20:\t\t stored : 26\t expected : 20 (esc)
    device 21:\t\t stored : 17\t expected : 20 (esc)
    device 22:\t\t stored : 16\t expected : 20 (esc)
    device 23:\t\t stored : 16\t expected : 20 (esc)
    device 24:\t\t stored : 16\t expected : 20 (esc)
  rule 0 (replicated_ruleset) num_rep 7 result size == 3:\t2/100 (esc)
  rule 0 (replicated_ruleset) num_rep 7 result size == 4:\t42/100 (esc)
  rule 0 (replicated_ruleset) num_rep 7 result size == 5:\t56/100 (esc)
    device 0:\t\t stored : 1\t expected : 20 (esc)
    device 1:\t\t stored : 1\t expected : 20 (esc)
    device 2:\t\t stored : 95\t expected : 20 (esc)
    device 3:\t\t stored : 2\t expected : 20 (esc)
    device 4:\t\t stored : 1\t expected : 20 (esc)
    device 5:\t\t stored : 14\t expected : 20 (esc)
    device 6:\t\t stored : 14\t expected : 20 (esc)
    device 7:\t\t stored : 16\t expected : 20 (esc)
    device 8:\t\t stored : 19\t expected : 20 (esc)
    device 9:\t\t stored : 22\t expected : 20 (esc)
    device 10:\t\t stored : 15\t expected : 20 (esc)
    device 11:\t\t stored : 16\t expected : 20 (esc)
    device 12:\t\t stored : 17\t expected : 20 (esc)
    device 13:\t\t stored : 19\t expected : 20 (esc)
    device 14:\t\t stored : 20\t expected : 20 (esc)
    device 15:\t\t stored : 19\t expected : 20 (esc)
    device 16:\t\t stored : 20\t expected : 20 (esc)
    device 17:\t\t stored : 17\t expected : 20 (esc)
    device 18:\t\t stored : 15\t expected : 20 (esc)
    device 19:\t\t stored : 20\t expected : 20 (esc)
    device 20:\t\t stored : 26\t expected : 20 (esc)
    device 21:\t\t stored : 17\t expected : 20 (esc)
    device 22:\t\t stored : 16\t expected : 20 (esc)
    device 23:\t\t stored : 16\t expected : 20 (esc)
    device 24:\t\t stored : 16\t expected : 20 (esc)
  rule 0 (replicated_ruleset) num_rep 8 result size == 3:\t2/100 (esc)
  rule 0 (replicated_ruleset) num_rep 8 result size == 4:\t40/100 (esc)
  rule 0 (replicated_ruleset) num_rep 8 result size == 5:\t58/100 (esc)
    device 0:\t\t stored : 1\t expected : 20 (esc)
    device 1:\t\t stored : 1\t expected : 20 (esc)
    device 2:\t\t stored : 95\t expected : 20 (esc)
    device 3:\t\t stored : 2\t expected : 20 (esc)
    device 4:\t\t stored : 1\t expected : 20 (esc)
    device 5:\t\t stored : 14\t expected : 20 (esc)
    device 6:\t\t stored : 14\t expected : 20 (esc)
    device 7:\t\t stored : 16\t expected : 20 (esc)
    device 8:\t\t stored : 19\t expected : 20 (esc)
    device 9:\t\t stored : 22\t expected : 20 (esc)
    device 10:\t\t stored : 15\t expected : 20 (esc)
    device 11:\t\t stored : 16\t expected : 20 (esc)
    device 12:\t\t stored : 17\t expected : 20 (esc)
    device 13:\t\t stored : 20\t expected : 20 (esc)
    device 14:\t\t stored : 20\t expected : 20 (esc)
    device 15:\t\t stored : 19\t expected : 20 (esc)
    device 16:\t\t stored : 20\t expected : 20 (esc)
    device 17:\t\t stored : 17\t expected : 20 (esc)
    device 18:\t\t stored : 16\t expected : 20 (esc)
    device 19:\t\t stored : 20\t expected : 20 (esc)
    device 20:\t\t stored : 26\t expected : 20 (esc)
    device 21:\t\t stored : 17\t expected : 20 (esc)
    device 22:\t\t stored : 16\t expected : 20 (esc)
    device 23:\t\t stored : 16\t expected : 20 (esc)
    device 24:\t\t stored : 16\t expected : 20 (esc)
  rule 0 (replicated_ruleset) num_rep 9 result size == 3:\t2/100 (esc)
  rule 0 (replicated_ruleset) num_rep 9 result size == 4:\t37/100 (esc)
  rule 0 (replicated_ruleset) num_rep 9 result size == 5:\t61/100 (esc)
    device 0:\t\t stored : 1\t expected : 20 (esc)
    device 1:\t\t stored : 1\t expected : 20 (esc)
    device 2:\t\t stored : 95\t expected : 20 (esc)
    device 3:\t\t stored : 2\t expected : 20 (esc)
    device 4:\t\t stored : 1\t expected : 20 (esc)
    device 5:\t\t stored : 14\t expected : 20 (esc)
    device 6:\t\t stored : 14\t expected : 20 (esc)
    device 7:\t\t stored : 16\t expected : 20 (esc)
    device 8:\t\t stored : 19\t expected : 20 (esc)
    device 9:\t\t stored : 23\t expected : 20 (esc)
    device 10:\t\t stored : 15\t expected : 20 (esc)
    device 11:\t\t stored : 16\t expected : 20 (esc)
    device 12:\t\t stored : 17\t expected : 20 (esc)
    device 13:\t\t stored : 20\t expected : 20 (esc)
    device 14:\t\t stored : 21\t expected : 20 (esc)
    device 15:\t\t stored : 19\t expected : 20 (esc)
    device 16:\t\t stored : 20\t expected : 20 (esc)
    device 17:\t\t stored : 18\t expected : 20 (esc)
    device 18:\t\t stored : 16\t expected : 20 (esc)
    device 19:\t\t stored : 20\t expected : 20 (esc)
    device 20:\t\t stored : 26\t expected : 20 (esc)
    device 21:\t\t stored : 17\t expected : 20 (esc)
    device 22:\t\t stored : 16\t expected : 20 (esc)
    device 23:\t\t stored : 16\t expected : 20 (esc)
    device 24:\t\t stored : 16\t expected : 20 (esc)
  rule 0 (replicated_ruleset) num_rep 10 result size == 3:\t2/100 (esc)
  rule 0 (replicated_ruleset) num_rep 10 result size == 4:\t36/100 (esc)
  rule 0 (replicated_ruleset) num_rep 10 result size == 5:\t62/100 (esc)
    device 0:\t\t stored : 1\t expected : 20 (esc)
    device 1:\t\t stored : 1\t expected : 20 (esc)
    device 2:\t\t stored : 95\t expected : 20 (esc)
    device 3:\t\t stored : 2\t expected : 20 (esc)
    device 4:\t\t stored : 1\t expected : 20 (esc)
    device 5:\t\t stored : 14\t expected : 20 (esc)
    device 6:\t\t stored : 14\t expected : 20 (esc)
    device 7:\t\t stored : 16\t expected : 20 (esc)
    device 8:\t\t stored : 19\t expected : 20 (esc)
    device 9:\t\t stored : 23\t expected : 20 (esc)
    device 10:\t\t stored : 15\t expected : 20 (esc)
    device 11:\t\t stored : 17\t expected : 20 (esc)
    device 12:\t\t stored : 17\t expected : 20 (esc)
    device 13:\t\t stored : 20\t expected : 20 (esc)
    device 14:\t\t stored : 21\t expected : 20 (esc)
    device 15:\t\t stored : 19\t expected : 20 (esc)
    device 16:\t\t stored : 20\t expected : 20 (esc)
    device 17:\t\t stored : 18\t expected : 20 (esc)
    device 18:\t\t stored : 16\t expected : 20 (esc)
    device 19:\t\t stored : 20\t expected : 20 (esc)
    device 20:\t\t stored : 26\t expected : 20 (esc)
    device 21:\t\t stored : 17\t expected : 20 (esc)
    device 22:\t\t stored : 16\t expected : 20 (esc)
    device 23:\t\t stored : 16\t expected : 20 (esc)
    device 24:\t\t stored : 16\t expected : 20 (esc)
  crushtool successfully built or modified map.  Use '-o <file>' to write it out.
