// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include <cstddef>
#include <utility>
#include <type_traits>

namespace ceph {
// `static_ptr`
// ===========
//
// It would be really nice if polymorphism didn't require a bunch of
// mucking about with the heap. So let's build something where we
// don't have to do that.
//
namespace _mem {

// This, an operator function, is one of the canonical ways to do type
// erasure in C++ so long as all operations can be done with subsets
// of the same arguments (which is not true for function type erasure)
// it's a pretty good one.
enum class op {
  copy, move, destroy, size
};
// B is the base pointer type of the class that first created the
// function/datum. It's only used to control copy/move support and
// noexcept annotation. Since the ward in static_ptr_base only allows
// moves/copies from more permissive to less, we should never end up
// with a situation where static_ptr thinks we should be able to copy
// or move something that can't unless people abuse
// reinterpret_pointer_cast. But it's a reinterpreting cast. They know
// what they're getting into.
template<typename B, typename T>
static std::size_t op_fun(op oper, void* p1, void* p2)
  noexcept((!std::is_copy_constructible_v<B> ||
	    std::is_nothrow_copy_constructible_v<B>) &&
	   (!std::is_move_constructible_v<B> ||
	    std::is_nothrow_move_constructible_v<B>)) {
  auto me = static_cast<T*>(p1);

  if constexpr (std::is_copy_constructible_v<B>) {
    if (oper == op::copy) {
      new (p2) T(*me);
      return 0;
    }
  }

  if constexpr (std::is_move_constructible_v<B>) {
    if (oper == op::move) {
      new (p2) T(std::move(*me));
      return 0;
    }
  }

  if (oper == op::destroy) {
    me->~T();
    return 0;
  }

  if (oper == op::size) {
    return sizeof(T);
  }
  std::terminate();
}
template<typename Base, std::size_t Size>
class static_ptr_base
{
protected:
  template<typename U, std::size_t S>
  friend class static_ptr_base;

  // Guard us from any unsafe construction or assignment.
  template<typename T, std::size_t S>
  constexpr static int create_ward() noexcept {
    static_assert(std::is_void_v<Base> ||
                  std::is_base_of_v<Base, std::decay_t<T>>,
                  "Value to store must be a derivative of the base.");
    // Never eat anything bigger than you are.
    static_assert(S <= Size, "Value too large.");
    static_assert(std::is_void_v<Base> || !std::is_const<Base>{} ||
                  std::is_const_v<T>,
                  "Cannot assign const pointer to non-const pointer.");
    static_assert(!std::is_copy_constructible_v<Base> ||
		  std::is_copy_constructible_v<T>,
		  "The pointer type is copyable, so any stored type must be "
		  "copyable.");
    static_assert(!std::is_nothrow_copy_constructible_v<Base> ||
		  std::is_nothrow_copy_constructible_v<T>,
		  "The pointer type is nothrow copyable, so any stored type must "
		  "be nothrow copyable.");
    static_assert(!std::is_move_constructible_v<Base> ||
		  std::is_move_constructible_v<T>,
		  "The pointer type is movable, so any stored type must be "
		  "movable.");
    static_assert(!std::is_nothrow_move_constructible_v<Base> ||
		  std::is_nothrow_move_constructible_v<T>,
		  "The pointer type is nothrow movable, so any stored type must "
		  "be nothrow movable.");
    return 0;
  }
  // Here we can store anything that has the same signature, which is
  // relevant to the multiple-versions for move/copy support that I
  // mentioned above.
  //
  size_t (*operate)(_mem::op, void*, void*)
    noexcept((!std::is_copy_constructible_v<Base> ||
	      std::is_nothrow_copy_constructible_v<Base>) &&
	     (!std::is_move_constructible_v<Base> ||
	      std::is_nothrow_move_constructible_v<Base>));

  // This is mutable so that get and the dereference operators can be
  // const. Since we're modeling a pointer, we should preserve the
  // difference in semantics between a pointer-to-const and a const
  // pointer.
  //
  mutable typename std::aligned_storage<Size>::type buf;

public:
  using element_type = Base;
  using pointer = Base*;

  // Empty
  static_ptr_base() noexcept : operate(nullptr) {}
  static_ptr_base(std::nullptr_t) noexcept : operate(nullptr) {}
  static_ptr_base& operator =(std::nullptr_t) noexcept {
    reset();
    return *this;
  }
  ~static_ptr_base() noexcept {
    reset();
  }

  // Since other pointer-ish types have it
  void reset() noexcept {
    if (operate) {
      operate(_mem::op::destroy, &buf, nullptr);
      operate = nullptr;
    }
  }

  // Set from another static pointer.
  template<typename U, std::size_t S>
  static_ptr_base(const static_ptr_base<U, S>& rhs)
    noexcept(std::is_nothrow_copy_constructible_v<U>) : operate(rhs.operate) {
    create_ward<U, S>();
    if (operate) {
      operate(_mem::op::copy, &rhs.buf, &buf);
    }
  }
  template<typename U, std::size_t S>
  static_ptr_base(static_ptr_base<U, S>&& rhs)
    noexcept(std::is_nothrow_move_constructible_v<U>) : operate(rhs.operate) {
    create_ward<U, S>();
    if (operate) {
      operate(_mem::op::move, &rhs.buf, &buf);
    }
  }

  template<typename U, std::size_t S>
  static_ptr_base& operator =(const static_ptr_base<U, S>& rhs)
    noexcept(std::is_nothrow_copy_constructible_v<U>) {
    create_ward<U, S>();
    reset();
    if (rhs) {
      operate = rhs.operate;
      operate(_mem::op::copy,
	      const_cast<void*>(static_cast<const void*>(&rhs.buf)), &buf);
    }
    return *this;
  }
  template<typename U, std::size_t S>
  static_ptr_base& operator =(static_ptr_base<U, S>&& rhs)
    noexcept(std::is_nothrow_move_constructible_v<U>) {
    create_ward<U, S>();
    reset();
    if (rhs) {
      operate = rhs.operate;
      operate(_mem::op::move, &rhs.buf, &buf);
    }
    return *this;
  }

  // In-place construction!
  //
  // This is basically what you want, and I didn't include value
  // construction because in-place construction renders it
  // unnecessary. Also it doesn't fit the pointer idiom as well.
  //
  template<typename T, typename... Args>
  static_ptr_base(std::in_place_type_t<T>, Args&& ...args)
    noexcept(std::is_nothrow_constructible_v<T, Args...>)
    : operate(&op_fun<Base, T>){
    create_ward<T, sizeof(T)>();
    new (&buf) T(std::forward<Args>(args)...);
  }

  // I occasionally get tempted to make an overload of the assignment
  // operator that takes a tuple as its right-hand side to provide
  // arguments.
  //
  template<typename T, typename... Args>
  void emplace(Args&& ...args)
    noexcept(std::is_nothrow_constructible_v<T, Args...>) {
    create_ward<T, sizeof(T)>();
    reset();
    operate = &op_fun<Base, T>;
    new (&buf) T(std::forward<Args>(args)...);
  }

  // Access!
  Base* get() const noexcept {
    return operate ? reinterpret_cast<Base*>(&buf) : nullptr;
  }
  template<typename U = Base>
  std::enable_if_t<!std::is_void_v<U>, Base*> operator->() const noexcept {
    return get();
  }
  template<typename U = Base>
  std::enable_if_t<!std::is_void_v<U>, Base&> operator *() const noexcept {
    return *get();
  }
  operator bool() const noexcept {
    return !!operate;
  }
};
}
// The top-level class!
//
// The default value for Size may be wrong in almost all cases. You
// can change it to your heart's content. The upside is that you'll
// just get a compile error and you can bump it up.
//
// I *recommend* having a size constant in header files (or perhaps a
// using declaration, e.g.
// ```
// using StaticFoo = static_ptr<Foo, sizeof(Blah)>`
// ```
// in some header file that can be used multiple places) so that when
// you create a new derived class with a larger size, you only have to
// change it in one place.
//
// I split things out this way since it lets me enable or disable
// move/copy constructors and assignment operators.
//
// Beware that an abstract base class is /not/ copy constructible, so
// if you create a static_ptr to one, you will never be able to copy
// or move from it.
//
template<typename Base, std::size_t Size = sizeof(Base),
	 bool C = std::is_copy_constructible_v<Base>,
	 bool M = std::is_move_constructible_v<Base>>
class static_ptr;

// Copy/Move
template<typename Base, std::size_t Size>
class static_ptr<Base, Size, true, true>
  : public _mem::static_ptr_base<Base, Size>
{
  using _mem::static_ptr_base<Base, Size>::operate;
  using _mem::static_ptr_base<Base, Size>::buf;

public:
  using element_type = Base;
  using pointer = Base*;

  using _mem::static_ptr_base<Base, Size>::static_ptr_base;
  using _mem::static_ptr_base<Base, Size>::reset;
  using _mem::static_ptr_base<Base, Size>::emplace;
  using _mem::static_ptr_base<Base, Size>::operator =;

  // Since the templated versions don't count for overriding the defaults
  static_ptr(const static_ptr& rhs)
    noexcept(std::is_nothrow_copy_constructible_v<Base>) {
    operate = rhs.operate;
    if (operate) {
      operate(_mem::op::copy, &rhs.buf, &buf);
    }
  }
  static_ptr(static_ptr&& rhs)
    noexcept(std::is_nothrow_move_constructible_v<Base>) {
    operate = rhs.operate;
    if (operate) {
      operate(_mem::op::move, &rhs.buf, &buf);
    }
  }

  static_ptr& operator =(const static_ptr& rhs)
    noexcept(std::is_nothrow_copy_constructible_v<Base>) {
    reset();
    if (rhs) {
      operate = rhs.operate;
      operate(_mem::op::copy,
	      const_cast<void*>(static_cast<const void*>(&rhs.buf)), &buf);
    }
    return *this;
  }
  static_ptr& operator =(static_ptr&& rhs)
    noexcept(std::is_nothrow_move_constructible_v<Base>) {
    reset();
    if (rhs) {
      operate = rhs.operate;
      operate(_mem::op::move, &rhs.buf, &buf);
    }
    return *this;
  }

  // Big wall of friendship
  //
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  static_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  static_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  dynamic_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  dynamic_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  const_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  const_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  reinterpret_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  reinterpret_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  resize_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  resize_pointer_cast(static_ptr<T, S>&& p);
};

// Copy only
template<typename Base, std::size_t Size>
class static_ptr<Base, Size, true, false>
  : public _mem::static_ptr_base<Base, Size>
{
  using _mem::static_ptr_base<Base, Size>::operate;
  using _mem::static_ptr_base<Base, Size>::buf;

public:
  using element_type = Base;
  using pointer = Base*;

  using _mem::static_ptr_base<Base, Size>::static_ptr_base;
  using _mem::static_ptr_base<Base, Size>::reset;
  using _mem::static_ptr_base<Base, Size>::emplace;
  using _mem::static_ptr_base<Base, Size>::operator =;

  // Since the templated versions don't count for overriding the defaults
  static_ptr(const static_ptr& rhs)
    noexcept(std::is_nothrow_copy_constructible_v<Base>) {
    operate = rhs.operate;
    if (operate) {
      operate(_mem::op::copy, &rhs.buf, &buf);
    }
  }
  static_ptr(static_ptr&& rhs) = delete;

  static_ptr& operator =(const static_ptr& rhs)
    noexcept(std::is_nothrow_copy_constructible_v<Base>) {
    reset();
    if (rhs) {
      operate = rhs.operate;
      operate(_mem::op::copy,
	      const_cast<void*>(static_cast<const void*>(&rhs.buf)), &buf);
    }
    return *this;
  }
  static_ptr& operator =(static_ptr&& rhs) = delete;

  // Big wall of friendship
  //
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  static_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  static_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  dynamic_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  dynamic_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  const_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  const_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  reinterpret_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  reinterpret_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  resize_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  resize_pointer_cast(static_ptr<T, S>&& p);
};

// Move only
template<typename Base, std::size_t Size>
class static_ptr<Base, Size, false, true>
  : public _mem::static_ptr_base<Base, Size>
{
  using _mem::static_ptr_base<Base, Size>::operate;
  using _mem::static_ptr_base<Base, Size>::buf;

public:
  using element_type = Base;
  using pointer = Base*;

  using _mem::static_ptr_base<Base, Size>::static_ptr_base;
  using _mem::static_ptr_base<Base, Size>::reset;
  using _mem::static_ptr_base<Base, Size>::emplace;
  using _mem::static_ptr_base<Base, Size>::operator =;

  // Since the templated versions don't count for overriding the defaults
  static_ptr(const static_ptr& rhs) = delete;
  static_ptr(static_ptr&& rhs)
    noexcept(std::is_nothrow_move_constructible_v<Base>) {
    operate = rhs.operate;
    if (operate) {
      operate(_mem::op::move, &rhs.buf, &buf);
    }
  }

  static_ptr& operator =(const static_ptr& rhs) = delete;
  static_ptr& operator =(static_ptr&& rhs)
    noexcept(std::is_nothrow_move_constructible_v<Base>) {
    reset();
    if (rhs) {
      operate = rhs.operate;
      operate(_mem::op::move, &rhs.buf, &buf);
    }
    return *this;
  }

  // Big wall of friendship
  //
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  static_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  static_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  dynamic_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  dynamic_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  const_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  const_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  reinterpret_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  reinterpret_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  resize_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  resize_pointer_cast(static_ptr<T, S>&& p);
};

// Neither/nor
template<typename Base, std::size_t Size>
class static_ptr<Base, Size, false, false>
  : public _mem::static_ptr_base<Base, Size>
{
  using _mem::static_ptr_base<Base, Size>::operate;
  using _mem::static_ptr_base<Base, Size>::buf;

public:
  using element_type = Base;
  using pointer = Base*;

  using _mem::static_ptr_base<Base, Size>::static_ptr_base;
  using _mem::static_ptr_base<Base, Size>::reset;
  using _mem::static_ptr_base<Base, Size>::emplace;
  using _mem::static_ptr_base<Base, Size>::operator =;

  // Since the templated versions don't count for overriding the defaults
  static_ptr(const static_ptr& rhs) = delete;
  static_ptr(static_ptr&& rhs) = delete;

  static_ptr& operator =(const static_ptr& rhs) = delete;
  static_ptr& operator =(static_ptr&& rhs) = delete;

  // Big wall of friendship
  //
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  static_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  static_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  dynamic_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  dynamic_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  const_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  const_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  reinterpret_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  reinterpret_pointer_cast(static_ptr<T, S>&& p);

  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
  resize_pointer_cast(const static_ptr<T, S>& p);
  template<typename U, std::size_t Z, typename T, std::size_t S>
  friend std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
  resize_pointer_cast(static_ptr<T, S>&& p);
};

// These are all modeled after the same ones for shared pointer.
//
// Also I'm annoyed that the standard library doesn't have
// *_pointer_cast overloads for a move-only unique pointer. It's a
// nice idiom. Having to release and reconstruct is obnoxious.
//
template<typename U, std::size_t Z, typename T, std::size_t S>
std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
static_pointer_cast(const static_ptr<T, S>& p) {
  static_assert(Z >= S,
                "Value too large.");
  static_ptr<U, Z> r;
  // Really, this is always true because static_cast either succeeds
  // or fails to compile, but it prevents an unused variable warning
  // and should be optimized out.
  if (static_cast<U*>(p.get())) {
    p.operate(_mem::op::copy, &p.buf, &r.buf);
    r.operate = p.operate;
  }
  return r;
}
template<typename U, std::size_t Z, typename T, std::size_t S>
std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
static_pointer_cast(static_ptr<T, S>&& p) {
  static_assert(Z >= S,
                "Value too large.");
  static_ptr<U, Z> r;
  if (static_cast<U*>(p.get())) {
    p.operate(_mem::op::move, &p.buf, &r.buf);
    r.operate = p.operate;
  }
  return r;
}

// Here the conditional is actually important and ensures we have the
// same behavior as dynamic_cast.
//
template<typename U, std::size_t Z, typename T, std::size_t S>
std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
dynamic_pointer_cast(const static_ptr<T, S>& p) {
  static_assert(Z >= S,
                "Value too large.");
  static_ptr<U, Z> r;
  if (dynamic_cast<U*>(p.get())) {
    p.operate(_mem::op::copy, &p.buf, &r.buf);
    r.operate = p.operate;
  }
  return r;
}
template<typename U, std::size_t Z, typename T, std::size_t S>
std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
dynamic_pointer_cast(static_ptr<T, S>&& p) {
  static_assert(Z >= S,
                "Value too large.");
  static_ptr<U, Z> r;
  if (dynamic_cast<U*>(p.get())) {
    p.operate(_mem::op::move, &p.buf, &r.buf);
    r.operate = p.operate;
  }
  return r;
}

template<typename U, std::size_t Z, typename T, std::size_t S>
std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
const_pointer_cast(const static_ptr<T, S>& p) {
  static_assert(Z >= S,
                "Value too large.");
  static_ptr<U, Z> r;
  if (const_cast<U*>(p.get())) {
    p.operate(_mem::op::copy, &p.buf, &r.buf);
    r.operate = p.operate;
  }
  return r;
}
template<typename U, std::size_t Z, typename T, std::size_t S>
std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
const_pointer_cast(static_ptr<T, S>&& p) {
  static_assert(Z >= S,
                "Value too large.");
  static_ptr<U, Z> r;
  if (const_cast<U*>(p.get())) {
    p.operate(_mem::op::move, &p.buf, &r.buf);
    r.operate = p.operate;
  }
  return r;
}

// I'm not sure if anyone will ever use this. I can imagine situations
// where they might. It works, though!
//
template<typename U, std::size_t Z, typename T, std::size_t S>
std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
reinterpret_pointer_cast(const static_ptr<T, S>& p) {
  static_assert(Z >= S,
                "Value too large.");
  static_ptr<U, Z> r;
  p.operate(_mem::op::copy, &p.buf, &r.buf);
  r.operate = p.operate;
  return r;
}
template<typename U, std::size_t Z, typename T, std::size_t S>
std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
reinterpret_pointer_cast(static_ptr<T, S>&& p) {
  static_assert(Z >= S,
                "Value too large.");
  static_ptr<U, Z> r;
  p.operate(_mem::op::move, &p.buf, &r.buf);
  r.operate = p.operate;
  return r;
}

// This is the only way to move from a bigger static pointer into a
// smaller static pointer. The size of the total data stored in the
// pointer is checked at runtime and if the destination size is large
// enough, we copy it over.
//
// I follow cast semantics. Since this is a pointer-like type, it
// returns a null value rather than throwing.
template<typename U, std::size_t Z, typename T, std::size_t S>
std::enable_if_t<std::is_copy_constructible_v<T>, static_ptr<U, Z>>
resize_pointer_cast(const static_ptr<T, S>& p) {
  static_assert(std::is_same_v<U, T>,
                "resize_pointer_cast only changes size, not type.");
  static_ptr<U, Z> r;
  if (Z >= p.operate(_mem::op::size, &p.buf, nullptr)) {
    p.operate(_mem::op::copy, &p.buf, &r.buf);
    r.operate = p.operate;
  }
  return r;
}
template<typename U, std::size_t Z, typename T, std::size_t S>
std::enable_if_t<std::is_move_constructible_v<T>, static_ptr<U, Z>>
resize_pointer_cast(static_ptr<T, S>&& p) {
  static_assert(std::is_same_v<U, T>,
                "resize_pointer_cast only changes size, not type.");
  static_ptr<U, Z> r;
  if (Z >= p.operate(_mem::op::size, &p.buf, nullptr)) {
    p.operate(_mem::op::move, &p.buf, &r.buf);
    r.operate = p.operate;
  }
  return r;
}

template<typename Base, std::size_t Size>
bool operator ==(const static_ptr<Base, Size>& s, std::nullptr_t) {
  return !s;
}
template<typename Base, std::size_t Size>
bool operator ==(std::nullptr_t, const static_ptr<Base, Size>& s) {
  return !s;
}

// Since `make_unique` and `make_shared` exist, we should follow their
// lead.
//
template<typename Base, typename Derived = Base,
         std::size_t Size = sizeof(Derived), typename... Args>
static_ptr<Base, Size> make_static(Args&& ...args) {
  return { std::in_place_type<Derived>, std::forward<Args>(args)... };
}
}
