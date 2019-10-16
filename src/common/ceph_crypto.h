// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
#ifndef CEPH_CRYPTO_H
#define CEPH_CRYPTO_H

#include "acconfig.h"
#include <stdexcept>

#include "include/buffer.h"
#include "include/types.h"

#define CEPH_CRYPTO_MD5_DIGESTSIZE 16
#define CEPH_CRYPTO_HMACSHA1_DIGESTSIZE 20
#define CEPH_CRYPTO_SHA1_DIGESTSIZE 20
#define CEPH_CRYPTO_HMACSHA256_DIGESTSIZE 32
#define CEPH_CRYPTO_SHA256_DIGESTSIZE 32
#define CEPH_CRYPTO_SHA512_DIGESTSIZE 64

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/hmac.h>
#include "blake2/sse/blake2.h"

#include "include/ceph_assert.h"

extern "C" {
  const EVP_MD *EVP_md5(void);
  const EVP_MD *EVP_sha1(void);
  const EVP_MD *EVP_sha256(void);
  const EVP_MD *EVP_sha512(void);
}

namespace ceph {
  namespace crypto {
    void assert_init();
    void init();
    void shutdown(bool shared=true);
  }
}

namespace ceph {
  namespace crypto {
    class DigestException : public std::runtime_error
    {
    public:
      DigestException(const char* what_arg) : runtime_error(what_arg)
	{}
    };

    class Blake2B
    {
    private:
      blake2bp_state s;
    public:
      static constexpr uint16_t digest_size =
	BLAKE2B_OUTBYTES /* 64 */;

      Blake2B() {
	Restart();
      }

      void Restart() {
	(void) blake2bp_init(&s, digest_size);
      }

      void Update(const unsigned char* data, uint64_t len) {
	blake2bp_update(&s, data, len);
      }

      void Final(unsigned char* digest) {
	blake2bp_final(&s, digest, digest_size);
      }
    };

    namespace ssl {
      class OpenSSLDigest {
      private:
	EVP_MD_CTX *mpContext;
	const EVP_MD *mpType;
      public:
	OpenSSLDigest (const EVP_MD *_type);
	~OpenSSLDigest ();

	OpenSSLDigest(const OpenSSLDigest&) = delete; // illegal

	/* these are ok */
	OpenSSLDigest(OpenSSLDigest&& rhs)
	  : mpContext(rhs.mpContext), mpType(rhs.mpType)
	  {
	    rhs.mpContext = nullptr;
	  }

	OpenSSLDigest& operator=(OpenSSLDigest&& rhs) {
	  mpContext = rhs.mpContext;
	  mpType = rhs.mpType;
	  rhs.mpContext = nullptr;
	  return *this;
	}

	void Restart();
	void Update (const unsigned char *input, size_t length);
	void Final (unsigned char *digest);
      };

      class MD5 : public OpenSSLDigest {
      public:
	static constexpr size_t digest_size = CEPH_CRYPTO_MD5_DIGESTSIZE;
	MD5 () : OpenSSLDigest(EVP_md5()) { }
      };

      class SHA1 : public OpenSSLDigest {
      public:
        static constexpr size_t digest_size = CEPH_CRYPTO_SHA1_DIGESTSIZE;
        SHA1 () : OpenSSLDigest(EVP_sha1()) { }
      };

      class SHA256 : public OpenSSLDigest {
      public:
        static constexpr size_t digest_size = CEPH_CRYPTO_SHA256_DIGESTSIZE;
        SHA256 () : OpenSSLDigest(EVP_sha256()) { }
      };

      class SHA512 : public OpenSSLDigest {
      public:
        static constexpr size_t digest_size = CEPH_CRYPTO_SHA512_DIGESTSIZE;
        SHA512 () : OpenSSLDigest(EVP_sha512()) { }
      };
    }
  }
}

namespace ceph::crypto::ssl {
# if OPENSSL_VERSION_NUMBER < 0x10100000L
  class HMAC {
  private:
    HMAC_CTX mContext;
    const EVP_MD *mpType;

  public:
    HMAC (const EVP_MD *type, const unsigned char *key, size_t length)
      : mpType(type) {
      ::memset(&mContext, 0, sizeof(mContext));
      const auto r = HMAC_Init_ex(&mContext, key, length, mpType, nullptr);
      if (r != 1) {
	  throw DigestException("HMAC_Init_ex() failed");
      }
    }
    ~HMAC () {
      HMAC_CTX_cleanup(&mContext);
    }

    void Restart () {
      const auto r = HMAC_Init_ex(&mContext, nullptr, 0, mpType, nullptr);
      if (r != 1) {
	throw DigestException("HMAC_Init_ex() failed");
      }
    }
    void Update (const unsigned char *input, size_t length) {
      if (length) {
        const auto r = HMAC_Update(&mContext, input, length);
	if (r != 1) {
	  throw DigestException("HMAC_Update() failed");
	}
      }
    }
    void Final (unsigned char *digest) {
      unsigned int s;
      const auto r = HMAC_Final(&mContext, digest, &s);
      if (r != 1) {
	throw DigestException("HMAC_Final() failed");
      }
    }
  };
# else
  class HMAC {
  private:
    HMAC_CTX *mpContext;

  public:
    HMAC (const EVP_MD *type, const unsigned char *key, size_t length)
      : mpContext(HMAC_CTX_new()) {
      const auto r = HMAC_Init_ex(mpContext, key, length, type, nullptr);
      if (r != 1) {
	throw DigestException("HMAC_Init_ex() failed");
      }
    }
    ~HMAC () {
      HMAC_CTX_free(mpContext);
    }

    void Restart () {
      const EVP_MD * const type = HMAC_CTX_get_md(mpContext);
      const auto r = HMAC_Init_ex(mpContext, nullptr, 0, type, nullptr);
      if (r != 1) {
	throw DigestException("HMAC_Init_ex() failed");
      }
    }
    void Update (const unsigned char *input, size_t length) {
      if (length) {
        const auto r = HMAC_Update(mpContext, input, length);
	if (r != 1) {
	  throw DigestException("HMAC_Update() failed");
	}
      }
    }
    void Final (unsigned char *digest) {
      unsigned int s;
      const auto r = HMAC_Final(mpContext, digest, &s);
      if (r != 1) {
	throw DigestException("HMAC_Final() failed");
      }
    }
  };
# endif // OPENSSL_VERSION_NUMBER < 0x10100000L

  struct HMACSHA1 : public HMAC {
    HMACSHA1 (const unsigned char *key, size_t length)
      : HMAC(EVP_sha1(), key, length) {
    }
  };

  struct HMACSHA256 : public HMAC {
    HMACSHA256 (const unsigned char *key, size_t length)
      : HMAC(EVP_sha256(), key, length) {
    }
  };
}


namespace ceph {
  namespace crypto {
    using ceph::crypto::ssl::SHA256;
    using ceph::crypto::ssl::MD5;
    using ceph::crypto::ssl::SHA1;
    using ceph::crypto::ssl::SHA512;

    using ceph::crypto::ssl::HMACSHA256;
    using ceph::crypto::ssl::HMACSHA1;
  }
}

namespace ceph::crypto {

template<class Digest>
inline void update(Digest& d, const ceph::buffer::list& bl)
{
  for (auto& p : bl.buffers()) {
    d.Update((const unsigned char *)p.c_str(), p.length());
  }
}

template<class Digest>
auto digest(const ceph::buffer::list& bl)
{
  unsigned char fingerprint[Digest::digest_size];
  Digest gen;
  update<Digest>(gen, bl);
  gen.Final(fingerprint);
  return sha_digest_t<Digest::digest_size>{fingerprint};
}
}

#endif
