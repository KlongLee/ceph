// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 * Copyright 2013 Inktank
 */

#ifndef HISTOGRAM_H_
#define HISTOGRAM_H_

/**
 * power of 2 histogram
 */
struct pow2_hist_t { //
  /**
   * histogram
   *
   * bin size is 2^index
   * value is count of elements that are <= the current bin but > the previous bin.
   */
  vector<int32_t> h;

private:
  /// expand to at least another's size
  void _expand_to(unsigned s) {
    if (s > h.size())
      h.resize(s, 0);
  }
  /// drop useless trailing 0's
  void _contract() {
    unsigned p = h.size();
    while (p > 0 && h[p-1] == 0)
      --p;
    h.resize(p);
  }

public:
  void clear() {
    h.clear();
  }
  void set(int bin, int32_t v) {
    _expand_to(bin + 1);
    h[bin] = v;
    _contract();
  }
  static int calc_bits_of(int t) {
    int b = 0;
    while (t > 0) {
      t = t >> 1;
      b++;
    }
    return b;
  }

  /// get a value's position in the histogram.
  ///
  /// positions are represented as values in the range [0..1000000]
  /// (millionths on the unit interval).
  ///
  /// @param v [in] value (non-negative)
  /// @param lower [out] pointer to lower-bound (0..1000000)
  /// @param upper [out] pointer to the upper bound (0..1000000)
  int get_position_micro(int32_t v, unsigned *lower, unsigned *upper) {
    if (v < 0)
      return -ERANGE;
    unsigned bin = calc_bits_of(v);
    unsigned lower_sum = 0, upper_sum = 0, total = 0;
    for (unsigned i=0; i<h.size(); ++i) {
      if (i <= bin)
	upper_sum += h[i];
      if (i < bin)
	lower_sum += h[i];
      total += h[i];
    }
    *lower = lower_sum * 1000000 / total;
    *upper = upper_sum * 1000000 / total;
    return 0;
  }

  void add(const pow2_hist_t& o) {
    _expand_to(o.h.size());
    for (unsigned p = 0; p < o.h.size(); ++p)
      h[p] += o.h[p];
    _contract();
  }
  void sub(const pow2_hist_t& o) {
    _expand_to(o.h.size());
    for (unsigned p = 0; p < o.h.size(); ++p)
      h[p] -= o.h[p];
    _contract();
  }

  int32_t upper_bound() const {
    return 1 << h.size();
  }

  void dump(Formatter *f) const;
  void encode(bufferlist &bl) const;
  void decode(bufferlist::iterator &bl);
  static void generate_test_instances(std::list<pow2_hist_t*>& o);
};
WRITE_CLASS_ENCODER(pow2_hist_t)

#endif /* HISTOGRAM_H_ */
