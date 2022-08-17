#include <algorithm>
#include <iterator>
#include <numeric>
#include <optional>
#include "common/perf_counters_cache_key.h"

namespace ceph::perf_counters::detail {

// use a null character to delimit strings
constexpr char delimiter = '\0';


// write a delimited string to the output
auto write(std::string_view str, std::output_iterator<char> auto out)
{
  out = std::copy(str.begin(), str.end(), out);
  *(out++) = delimiter;
  return out;
}

// return the encoded size of a label
inline std::size_t label_size(const label_pair& l)
{
  return l.first.size() + sizeof(delimiter)
      + l.second.size() + sizeof(delimiter);
}

// a forward iterator over label_pairs encoded on a flat buffer
class label_iterator {
  using base_iterator = const char*;

  struct iterator_state {
    base_iterator pos; // end of current label
    base_iterator end; // end of buffer
    label_pair label; // current label

    auto operator<=>(const iterator_state& rhs) const = default;
  };
  // an empty state represents a past-the-end iterator
  std::optional<iterator_state> state;

  // find the next two delimiters and construct the label string views
  static void advance(std::optional<iterator_state>& s)
  {
    auto d = std::find(s->pos, s->end, delimiter);
    if (d == s->end) { // no delimiter for label key
      s = std::nullopt;
      return;
    }
    s->label.first = std::string_view{s->pos, d};
    s->pos = std::next(d);

    d = std::find(s->pos, s->end, delimiter);
    if (d == s->end) { // no delimiter for label name
      s = std::nullopt;
      return;
    }
    s->label.second = std::string_view{s->pos, d};
    s->pos = std::next(d);
  }

  // try to parse the first label pair
  static auto make_state(base_iterator begin, base_iterator end)
  {
    std::optional state = iterator_state{begin, end};
    advance(state);
    return state;
  }

 public:
  using difference_type = std::ptrdiff_t;
  using value_type = label_pair;
  using pointer = const value_type*;
  using reference = const value_type&;

  label_iterator() = default;
  label_iterator(base_iterator begin, base_iterator end)
      : state(make_state(begin, end)) {
    static_assert(std::forward_iterator<label_iterator>);
  }

  label_iterator& operator++() {
    advance(state);
    return *this;
  }
  label_iterator operator++(int) {
    label_iterator tmp = *this;
    advance(state);
    return tmp;
  }

  reference operator*() const { return state->label; }
  pointer operator->() const { return &state->label; }

  auto operator<=>(const label_iterator& rhs) const = default;
};

// an output iterator that writes label_pairs to a flat buffer
template <std::contiguous_iterator Iterator>
class label_insert_iterator {
  using base_iterator = Iterator;

  struct label_writer {
    base_iterator pos; // write position

    label_writer& operator=(const label_pair& l) {
      pos = write(l.first, pos);
      pos = write(l.second, pos);
      return *this;
    }
  };
  label_writer label;

 public:
  using difference_type = std::ptrdiff_t;
  using value_type = label_writer;
  using reference = value_type&;

  label_insert_iterator(base_iterator begin) : label{begin} {
    static_assert(std::output_iterator<label_insert_iterator, label_pair>);
  }

  // increments are noops
  label_insert_iterator& operator++() { return *this; }
  label_insert_iterator operator++(int) { return *this; }

  // can only dereference to assign
  reference operator*() { return label; }

  // return the wrapped iterator position
  base_iterator base() { return label.pos; }
};

// compare label_pairs by their key only
struct label_key_less {
  bool operator()(const label_pair& lhs, const label_pair& rhs) const {
    return lhs.first < rhs.first;
  }
};
struct label_key_equal {
  bool operator()(const label_pair& lhs, const label_pair& rhs) const {
    return lhs.first == rhs.first;
  }
};

std::string create(std::string_view counter_name,
                   label_pair* begin, label_pair* end)
{
  // sort the input labels and remove duplicate keys
  std::sort(begin, end, label_key_less{});
  end = std::unique(begin, end, label_key_equal{});

  // calculate the total size and preallocate the buffer
  auto size = std::accumulate(begin, end,
                              counter_name.size() + sizeof(delimiter),
                              [] (std::size_t sum, const label_pair& l) {
                                return sum + label_size(l);
                              });
  std::string result;
  result.resize(size);

  // copy out the counter name and labels
  auto out = result.begin();
  out = write(counter_name, out);
  std::copy(begin, end, label_insert_iterator{out});

  return result;
}

std::string insert(const char* begin1, const char* end1,
                   label_pair* begin2, label_pair* end2)
{
  // sort the input labels and remove duplicate keys
  std::sort(begin2, end2, label_key_less{});
  end2 = std::unique(begin2, end2, label_key_equal{});

  // find the first delimiter that marks the end of the counter name
  auto pos = std::find(begin1, end1, delimiter);

  // calculate the total size and preallocate the buffer
  auto size = std::distance(begin1, end1);
  if (pos == end1) { // add a delimiter if the key doesn't have one
    size += sizeof(delimiter);
  }
  size = std::accumulate(begin2, end2, size,
                         [] (std::size_t sum, const label_pair& l) {
                           return sum + label_size(l);
                         });
  std::string result;
  result.resize(size);

  // copy the counter name without the delimiter
  auto out = std::copy(begin1, pos, result.begin());
  if (pos != end1) {
    ++pos; // advance past the delimiter
  }
  *(out++) = delimiter;

  // merge the two sorted input ranges, drop any duplicate keys, and write
  // them to output. the begin2 range is first so that new input labels can
  // replace existing duplicates
  auto end = std::set_union(begin2, end2,
                            label_iterator{pos, end1},
                            label_iterator{end1, end1},
                            label_insert_iterator{out},
                            label_key_less{});
  // fix up the size in case set_union() removed any duplicates
  result.resize(std::distance(result.begin(), end.base()));

  return result;
}

} // namespace ceph::perf_counters::detail
