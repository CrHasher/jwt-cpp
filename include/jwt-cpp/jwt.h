#pragma once
#define PICOJSON_USE_INT64
#include "picojson.h"
#include "base.h"
#include "errors.h"
#include <set>
#include <string>
#include <chrono>
#include <unordered_map>
#include <memory>
#include <cassert>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/err.h>

// If openssl version less than 1.1
#if OPENSSL_VERSION_NUMBER < 269484032
#define OPENSSL10
#endif

#ifndef JWT_CLAIM_EXPLICIT
#define JWT_CLAIM_EXPLICIT 0
#endif

namespace jwt
{
	using date = std::chrono::system_clock::time_point;

	namespace algorithm
	{
		/**
		 * "none" algorithm.
		 *
		 * Returns and empty signature and checks if the given signature is empty.
		 */
		struct none
		{
			/// Return an empty string
			result_t<std::string> sign(const std::string&) const
			{
				return {"", JwtErrc::NoError};
			}
			/// Check if the given signature is empty. JWT's with "none" algorithm should not contain a signature.
			JwtErrc verify(const std::string&, const std::string& signature) const
			{
				if (!signature.empty())
				{
					return JwtErrc::SignatureVerificationError;
				}
			}
			/// Get algorithm name
			std::string name() const
			{
				return "none";
			}
			JwtErrc error() const
			{
				return JwtErrc::NoError;
			}
		};
		/**
		 * Base class for HMAC family of algorithms
		 */
		struct hmacsha
		{
			/**
			 * Construct new hmac algorithm
			 * \param key Key to use for HMAC
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			hmacsha(std::string key, const EVP_MD* (*md)(), const std::string& name)
			    : secret(std::move(key))
			    , md(md)
			    , alg_name(name)
			{
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return HMAC signature for the given data
			 */
			result_t<std::string> sign(const std::string& data) const
			{
				result_t<std::string> res;
				res.first.resize(EVP_MAX_MD_SIZE);
				unsigned int len = res.first.size();
				if (HMAC(md(), secret.data(), secret.size(), (const unsigned char*)data.data(), data.size(),
				         (unsigned char*)res.first.data(), &len) == nullptr)
				{
					res.second = JwtErrc::SignatureGenerationError;
					return res;
				}
				res.first.resize(len);
				return res;
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 */
			JwtErrc verify(const std::string& data, const std::string& signature) const
			{
				auto res = sign(data);
				if (res.second != JwtErrc::NoError)
				{
					return res.second;
				}
				bool matched = true;
				for (size_t i = 0; i < std::min<size_t>(res.first.size(), signature.size()); i++)
					if (res.first[i] != signature[i])
						matched = false;
				if (res.first.size() != signature.size())
					matched = false;
				if (!matched)
					return JwtErrc::SignatureVerificationError;
				return JwtErrc::NoError;
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return Algorithmname
			 */
			std::string name() const
			{
				return alg_name;
			}
			JwtErrc error() const
			{
				return JwtErrc::NoError;
			}

		private:
			/// HMAC secrect
			const std::string secret;
			/// HMAC hash generator
			const EVP_MD* (*md)();
			/// Algorithmname
			const std::string alg_name;
		};
		/**
		 * Base class for RSA family of algorithms
		 */
		struct rsa
		{
			/**
			 * Construct new rsa algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			rsa(const std::string& public_key,
			    const std::string& private_key,
			    const std::string& public_key_password,
			    const std::string& private_key_password,
			    const EVP_MD* (*md)(),
			    const std::string& name)
			    : md(md)
			    , alg_name(name)
			    , construct_error_code(JwtErrc::NoError)
			{
				do
				{
					std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
					if ((size_t)BIO_write(pubkey_bio.get(), public_key.data(), public_key.size()) != public_key.size())
					{
						assert(0);
						construct_error_code = JwtErrc::FailedToLoadPublicKeyBioWriteError;
						break;
					}
					pkey.reset(
					    PEM_read_bio_PUBKEY(pubkey_bio.get(), nullptr, nullptr, (void*)public_key_password.c_str()),
					    EVP_PKEY_free);
					if (!pkey)
					{
						assert(0);
						construct_error_code = JwtErrc::FailedToLoadPublicKeyPemReadBioError;
						break;
					}
					if (!private_key.empty())
					{
						std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
						if ((size_t)BIO_write(privkey_bio.get(), private_key.data(), private_key.size()) !=
						    private_key.size())
						{
							assert(0);
							construct_error_code = JwtErrc::FailedToLoadPrivateKeyBioWriteError;
							break;
						}
						RSA* privkey = PEM_read_bio_RSAPrivateKey(privkey_bio.get(), nullptr, nullptr,
						                                          (void*)private_key_password.c_str());
						if (privkey == nullptr)
						{
							assert(0);
							construct_error_code = JwtErrc::FailedToLoadPrivateKeyPemReadBioError;
							break;
						}
						if (EVP_PKEY_assign_RSA(pkey.get(), privkey) == 0)
						{
							RSA_free(privkey);
							assert(0);
							construct_error_code = JwtErrc::FailedToLoadPrivateKeyEvpPKeyAssignRsaError;
							break;
						}
					}
				} while (0);
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return RSA signature for the given data
			 */
			result_t<std::string> sign(const std::string& data) const
			{
				result_t<std::string> res;
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
#endif
				if (!ctx)
				{
					res.second = JwtErrc::SignatureCreationContextCreationError;
					return res;
				}

				if (!EVP_SignInit(ctx.get(), md()))
				{
					res.second = JwtErrc::SignatureCreationSignInitError;
					return res;
				}

				res.first.resize(EVP_PKEY_size(pkey.get()));
				unsigned int len = 0;

				if (!EVP_SignUpdate(ctx.get(), data.data(), data.size()))
				{
					res.second = JwtErrc::SignatureGenerationError;
					return res;
				}
				if (!EVP_SignFinal(ctx.get(), (unsigned char*)res.first.data(), &len, pkey.get()))
				{
					res.second = JwtErrc::SignatureGenerationError;
					return res;
				}

				res.first.resize(len);
				return res;
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 */
			JwtErrc verify(const std::string& data, const std::string& signature) const
			{
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
#endif
				if (!ctx)
				{
					return JwtErrc::SignatureVerificationContextCreationError;
				}
				if (!EVP_VerifyInit(ctx.get(), md()))
				{
					return JwtErrc::SignatureVerificationVerifyInitError;
				}
				if (!EVP_VerifyUpdate(ctx.get(), data.data(), data.size()))
				{
					return JwtErrc::SignatureVerificationVerifyUpdateError;
				}
				if (!EVP_VerifyFinal(ctx.get(), (const unsigned char*)signature.data(), signature.size(), pkey.get()))
				{
					return JwtErrc::SignatureVerificationError;
				}
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return Algorithmname
			 */
			std::string name() const
			{
				return alg_name;
			}
			JwtErrc error() const
			{
				return construct_error_code;
			}

		private:
			/// OpenSSL structure containing converted keys
			std::shared_ptr<EVP_PKEY> pkey;
			/// Hash generator
			const EVP_MD* (*md)();
			/// Algorithmname
			const std::string alg_name;
			/// Error code
			JwtErrc construct_error_code;
		};
		/**
		 * Base class for ECDSA family of algorithms
		 */
		struct ecdsa
		{
			/**
			 * Construct new ecdsa algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always
			 * fail. \param public_key_password Password to decrypt public key pem. \param privat_key_password Password
			 * to decrypt private key pem. \param md Pointer to hash function \param name Name of the algorithm
			 */
			ecdsa(const std::string& public_key,
			      const std::string& private_key,
			      const std::string& public_key_password,
			      const std::string& private_key_password,
			      const EVP_MD* (*md)(),
			      const std::string& name)
			    : md(md)
			    , alg_name(name)
			    , construct_error_code(JwtErrc::NoError)
			{
				do
				{
					if (private_key.empty())
					{
						std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
						if ((size_t)BIO_write(pubkey_bio.get(), public_key.data(), public_key.size()) !=
						    public_key.size())
						{
							assert(0);
							construct_error_code = JwtErrc::FailedToLoadPublicKeyBioWriteError;
							break;
						}

						pkey.reset(PEM_read_bio_EC_PUBKEY(pubkey_bio.get(), nullptr, nullptr,
						                                  (void*)public_key_password.c_str()),
						           EC_KEY_free);
						if (!pkey)
						{
							assert(0);
							construct_error_code = JwtErrc::FailedToLoadPublicKeyPemReadBioError;
							break;
						}
					}
					else
					{
						std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
						if ((size_t)BIO_write(privkey_bio.get(), private_key.data(), private_key.size()) !=
						    private_key.size())
						{
							assert(0);
							construct_error_code = JwtErrc::FailedToLoadPrivateKeyBioWriteError;
							break;
						}
						pkey.reset(PEM_read_bio_ECPrivateKey(privkey_bio.get(), nullptr, nullptr,
						                                     (void*)private_key_password.c_str()),
						           EC_KEY_free);
						if (!pkey)
						{
							assert(0);
							construct_error_code = JwtErrc::FailedToLoadPrivateKeyPemReadBioError;
							break;
						}
					}
					if (EC_KEY_check_key(pkey.get()) == 0)
					{
						assert(0);
						construct_error_code = JwtErrc::FailedToLoadKeyInvalidError;
						break;
					}
				} while (0);
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return ECDSA signature for the given data
			 */
			result_t<std::string> sign(const std::string& data) const
			{
				result_t<std::string> res;
				result_t<std::string> hash = generate_hash(data);
				if (hash.second != JwtErrc::NoError)
				{
					res.second = hash.second;
					return res;
				}
				std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(
				    ECDSA_do_sign((const unsigned char*)hash.first.data(), hash.first.size(), pkey.get()),
				    ECDSA_SIG_free);
#ifdef OPENSSL10
				result_t<std::string> bn2RawSigR = bn2raw(sig->r);
				if (bn2RawSigR.second != JwtErrc::NoError)
				{
					res.second = bn2RawSigR.second;
					return res;
				}
				result_t<std::string> bn2RawSigS = bn2raw(sig->s);
				if (bn2RawSigS.second != JwtErrc::NoError)
				{
					res.second = bn2RawSigS.second;
					return res;
				}
				res.first = bn2RawSigR.first + bn2RawSigS.first;
				return res;
#else
				const BIGNUM* r;
				const BIGNUM* s;
				ECDSA_SIG_get0(sig.get(), &r, &s);
				result_t<std::string> bn2RawSigR = bn2raw(r);
				if (bn2RawSigR.second != JwtErrc::NoError)
				{
					res.second = bn2RawSigR.second;
					return res;
				}
				result_t<std::string> bn2RawSigS = bn2raw(s);
				if (bn2RawSigS.second != JwtErrc::NoError)
				{
					res.second = bn2RawSigS.second;
					return res;
				}
				res.first = bn2RawSigR.first + bn2RawSigS.first;
				return res;
#endif
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 */
			JwtErrc verify(const std::string& data, const std::string& signature) const
			{
				result_t<const std::string> hash = generate_hash(data);
				if (hash.second != JwtErrc::NoError)
				{
					return hash.second;
				}
				auto r = raw2bn(signature.substr(0, signature.size() / 2));
				if (r.second != JwtErrc::NoError)
				{
					return r.second;
				}
				auto s = raw2bn(signature.substr(signature.size() / 2));
				if (s.second != JwtErrc::NoError)
				{
					return s.second;
				}
#ifdef OPENSSL10
				ECDSA_SIG sig;
				sig.r = r.first.get();
				sig.s = s.first.get();

				if (ECDSA_do_verify((const unsigned char*)hash.first.data(), hash.first.size(), &sig, pkey.get()) != 1)
					return JwtErrc::SignatureInvalidError;
#else
				ECDSA_SIG* sig = ECDSA_SIG_new();

				ECDSA_SIG_set0(sig, r.get(), s.get());

				if (ECDSA_do_verify((const unsigned char*)hash.data(), hash.size(), sig, pkey.get()) != 1)
					return JwtErrc::SignatureInvalidError;
#endif
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return Algorithmname
			 */
			std::string name() const
			{
				return alg_name;
			}
			JwtErrc error() const
			{
				return construct_error_code;
			}

		private:
			/**
			 * Convert a OpenSSL BIGNUM to a std::string
			 * \param bn BIGNUM to convert
			 * \return bignum as string
			 */
#ifdef OPENSSL10
			static result_t<std::string> bn2raw(BIGNUM* bn)
#else
			static result_t<std::string> bn2raw(const BIGNUM* bn)
#endif
			{
				result_t<std::string> res;
				res.first.resize(BN_num_bytes(bn));
				BN_bn2bin(bn, (unsigned char*)res.first.data());
				if (res.first.size() % 2 == 1 && res.first[0] == 0x00)
					return {res.first.substr(1), JwtErrc::NoError};
				return res;
			}
			/**
			 * Convert an std::string to a OpenSSL BIGNUM
			 * \param raw String to convert
			 * \return BIGNUM representation
			 */
			static result_t<std::unique_ptr<BIGNUM, decltype(&BN_free)>> raw2bn(const std::string& raw)
			{
				if (static_cast<uint8_t>(raw[0]) >= 0x80)
				{
					std::string str(1, 0x00);
					str += raw;
					return {std::unique_ptr<BIGNUM, decltype(&BN_free)>(
					            BN_bin2bn((const unsigned char*)str.data(), str.size(), nullptr), BN_free),
					        JwtErrc::NoError};
				}
				return {std::unique_ptr<BIGNUM, decltype(&BN_free)>(
				            BN_bin2bn((const unsigned char*)raw.data(), raw.size(), nullptr), BN_free),
				        JwtErrc::NoError};
			}

			/**
			 * Hash the provided data using the hash function specified in constructor
			 * \param data Data to hash
			 * \return Hash of data
			 */
			result_t<std::string> generate_hash(const std::string& data) const
			{
				result_t<std::string> res;
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(),
				                                                               &EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
				if (EVP_DigestInit(ctx.get(), md()) == 0)
				{
					res.second = JwtErrc::SignatureGenerationEVPDigestInitError;
					return res;
				}
				if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 0)
				{
					res.second = JwtErrc::SignatureGenerationEVPDigestUpdateError;
					return res;
				}
				unsigned int len = 0;
				res.first.resize(EVP_MD_CTX_size(ctx.get()));
				if (EVP_DigestFinal(ctx.get(), (unsigned char*)res.first.data(), &len) == 0)
				{
					res.second = JwtErrc::SignatureGenerationEVPDigestFinalError;
					return res;
				}
				res.first.resize(len);
				return res;
			}

			/// OpenSSL struct containing keys
			std::shared_ptr<EC_KEY> pkey;
			/// Hash generator function
			const EVP_MD* (*md)();
			/// Algorithmname
			const std::string alg_name;
			/// Error code
			JwtErrc construct_error_code;
		};

		/**
		 * Base class for PSS-RSA family of algorithms
		 */
		struct pss
		{
			/**
			 * Construct new pss algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			pss(const std::string& public_key,
			    const std::string& private_key,
			    const std::string& public_key_password,
			    const std::string& private_key_password,
			    const EVP_MD* (*md)(),
			    const std::string& name)
			    : md(md)
			    , alg_name(name)
			    , construct_error_code(JwtErrc::NoError)
			{
				do
				{
					std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
					if ((size_t)BIO_write(pubkey_bio.get(), public_key.data(), public_key.size()) != public_key.size())
					{
						assert(0);
						construct_error_code = JwtErrc::FailedToLoadPublicKeyBioWriteError;
						break;
					}
					pkey.reset(
					    PEM_read_bio_PUBKEY(pubkey_bio.get(), nullptr, nullptr, (void*)public_key_password.c_str()),
					    EVP_PKEY_free);
					if (!pkey)
					{
						assert(0);
						construct_error_code = JwtErrc::FailedToLoadPublicKeyPemReadBioError;
						break;
					}

					if (!private_key.empty())
					{
						std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
						if ((size_t)BIO_write(privkey_bio.get(), private_key.data(), private_key.size()) !=
						    private_key.size())
						{
							assert(0);
							construct_error_code = JwtErrc::FailedToLoadPrivateKeyBioWriteError;
							break;
						}
						RSA* privkey = PEM_read_bio_RSAPrivateKey(privkey_bio.get(), nullptr, nullptr,
						                                          (void*)private_key_password.c_str());
						if (privkey == nullptr)
						{
							assert(0);
							construct_error_code = JwtErrc::FailedToLoadPrivateKeyPemReadBioError;
							break;
						}
						if (EVP_PKEY_assign_RSA(pkey.get(), privkey) == 0)
						{
							RSA_free(privkey);
							assert(0);
							construct_error_code = JwtErrc::FailedToLoadPrivateKeyEvpPKeyAssignRsaError;
							break;
						}
					}
				} while (0);
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return ECDSA signature for the given data
			 */
			result_t<std::string> sign(const std::string& data) const
			{
				result_t<std::string> res;
				result_t<std::string> hash = generate_hash(data);
				if (hash.second != JwtErrc::NoError)
				{
					res.second = hash.second;
					return res;
				}
				std::unique_ptr<RSA, decltype(&RSA_free)> key(EVP_PKEY_get1_RSA(pkey.get()), RSA_free);
				const int size = RSA_size(key.get());

				std::string padded(size, 0x00);
				if (!RSA_padding_add_PKCS1_PSS_mgf1(key.get(), (unsigned char*)padded.data(),
				                                    (const unsigned char*)hash.first.data(), md(), md(), -1))
				{
					res.second = JwtErrc::SignatureCreationRSAPaddingAddError;
					return res;
				}

				res.first = std::string(size, 0x00);
				if (RSA_private_encrypt(size, (const unsigned char*)padded.data(), (unsigned char*)res.first.data(),
				                        key.get(), RSA_NO_PADDING) < 0)
				{
					res.second = JwtErrc::SignatureCreationRSAPaddingAddError;
				}
				return res;
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 */
			JwtErrc verify(const std::string& data, const std::string& signature) const
			{
				result_t<std::string> hash = this->generate_hash(data);
				if (hash.second != JwtErrc::NoError)
				{
					return hash.second;
				}
				std::unique_ptr<RSA, decltype(&RSA_free)> key(EVP_PKEY_get1_RSA(pkey.get()), RSA_free);
				const int size = RSA_size(key.get());
				std::string sig(size, 0x00);
				if (!RSA_public_decrypt(signature.size(), (const unsigned char*)signature.data(),
				                        (unsigned char*)sig.data(), key.get(), RSA_NO_PADDING))
				{
					return JwtErrc::SignatureInvalidError;
				}
				if (!RSA_verify_PKCS1_PSS_mgf1(key.get(), (const unsigned char*)hash.first.data(), md(), md(),
				                               (const unsigned char*)sig.data(), -1))
				{
					return JwtErrc::SignatureInvalidError;
				}
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return Algorithmname
			 */
			std::string name() const
			{
				return alg_name;
			}
			JwtErrc error() const
			{
				return construct_error_code;
			}

		private:
			/**
			 * Hash the provided data using the hash function specified in constructor
			 * \param data Data to hash
			 * \return Hash of data
			 */
			result_t<std::string> generate_hash(const std::string& data) const
			{
				result_t<std::string> res;
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(),
				                                                               &EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
				if (EVP_DigestInit(ctx.get(), md()) == 0)
				{
					res.second = JwtErrc::SignatureGenerationEVPDigestInitError;
					return res;
				}
				if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 0)
				{
					res.second = JwtErrc::SignatureGenerationEVPDigestUpdateError;
					return res;
				}
				unsigned int len = 0;
				res.first.resize(EVP_MD_CTX_size(ctx.get()));
				if (EVP_DigestFinal(ctx.get(), (unsigned char*)res.first.data(), &len) == 0)
				{
					res.second = JwtErrc::SignatureGenerationEVPDigestFinalError;
					return res;
				}
				res.first.resize(len);
				return res;
			}

			/// OpenSSL structure containing keys
			std::shared_ptr<EVP_PKEY> pkey;
			/// Hash generator function
			const EVP_MD* (*md)();
			/// Algorithmname
			const std::string alg_name;
			/// Error code
			JwtErrc construct_error_code;
		};

		/**
		 * HS256 algorithm
		 */
		struct hs256 : public hmacsha
		{
			/**
			 * Construct new instance of algorithm
			 * \param key HMAC signing key
			 */
			explicit hs256(std::string key)
			    : hmacsha(std::move(key), EVP_sha256, "HS256")
			{
			}
		};
		/**
		 * HS384 algorithm
		 */
		struct hs384 : public hmacsha
		{
			/**
			 * Construct new instance of algorithm
			 * \param key HMAC signing key
			 */
			explicit hs384(std::string key)
			    : hmacsha(std::move(key), EVP_sha384, "HS384")
			{
			}
		};
		/**
		 * HS512 algorithm
		 */
		struct hs512 : public hmacsha
		{
			/**
			 * Construct new instance of algorithm
			 * \param key HMAC signing key
			 */
			explicit hs512(std::string key)
			    : hmacsha(std::move(key), EVP_sha512, "HS512")
			{
			}
		};
		/**
		 * RS256 algorithm
		 */
		struct rs256 : public rsa
		{
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 */
			rs256(const std::string& public_key,
			      const std::string& private_key = "",
			      const std::string& public_key_password = "",
			      const std::string& private_key_password = "")
			    : rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "RS256")
			{
			}
		};
		/**
		 * RS384 algorithm
		 */
		struct rs384 : public rsa
		{
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 */
			rs384(const std::string& public_key,
			      const std::string& private_key = "",
			      const std::string& public_key_password = "",
			      const std::string& private_key_password = "")
			    : rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "RS384")
			{
			}
		};
		/**
		 * RS512 algorithm
		 */
		struct rs512 : public rsa
		{
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 */
			rs512(const std::string& public_key,
			      const std::string& private_key = "",
			      const std::string& public_key_password = "",
			      const std::string& private_key_password = "")
			    : rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "RS512")
			{
			}
		};
		/**
		 * ES256 algorithm
		 */
		struct es256 : public ecdsa
		{
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always
			 * fail. \param public_key_password Password to decrypt public key pem. \param privat_key_password Password
			 * to decrypt private key pem.
			 */
			es256(const std::string& public_key,
			      const std::string& private_key = "",
			      const std::string& public_key_password = "",
			      const std::string& private_key_password = "")
			    : ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "ES256")
			{
			}
		};
		/**
		 * ES384 algorithm
		 */
		struct es384 : public ecdsa
		{
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always
			 * fail. \param public_key_password Password to decrypt public key pem. \param privat_key_password Password
			 * to decrypt private key pem.
			 */
			es384(const std::string& public_key,
			      const std::string& private_key = "",
			      const std::string& public_key_password = "",
			      const std::string& private_key_password = "")
			    : ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "ES384")
			{
			}
		};
		/**
		 * ES512 algorithm
		 */
		struct es512 : public ecdsa
		{
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always
			 * fail. \param public_key_password Password to decrypt public key pem. \param privat_key_password Password
			 * to decrypt private key pem.
			 */
			es512(const std::string& public_key,
			      const std::string& private_key = "",
			      const std::string& public_key_password = "",
			      const std::string& private_key_password = "")
			    : ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "ES512")
			{
			}
		};

		/**
		 * PS256 algorithm
		 */
		struct ps256 : public pss
		{
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 */
			ps256(const std::string& public_key,
			      const std::string& private_key = "",
			      const std::string& public_key_password = "",
			      const std::string& private_key_password = "")
			    : pss(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "PS256")
			{
			}
		};
		/**
		 * PS384 algorithm
		 */
		struct ps384 : public pss
		{
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 */
			ps384(const std::string& public_key,
			      const std::string& private_key = "",
			      const std::string& public_key_password = "",
			      const std::string& private_key_password = "")
			    : pss(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "PS384")
			{
			}
		};
		/**
		 * PS512 algorithm
		 */
		struct ps512 : public pss
		{
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 */
			ps512(const std::string& public_key,
			      const std::string& private_key = "",
			      const std::string& public_key_password = "",
			      const std::string& private_key_password = "")
			    : pss(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "PS512")
			{
			}
		};
	} // namespace algorithm

	/**
	 * Convenience wrapper for JSON value
	 */
	class claim
	{
		picojson::value val;

	public:
		enum class type
		{
			null,
			boolean,
			number,
			string,
			array,
			object,
			int64
		};

		claim()
		    : val()
		{
		}
#if JWT_CLAIM_EXPLICIT
		explicit claim(std::string s)
		    : val(std::move(s))
		{
		}
		explicit claim(const date& s)
		    : val(int64_t(std::chrono::system_clock::to_time_t(s)))
		{
		}
		explicit claim(const std::set<std::string>& s)
		    : val(picojson::array(s.cbegin(), s.cend()))
		{
		}
		explicit claim(const picojson::value& val)
		    : val(val)
		{
		}
#else
		claim(std::string s)
		    : val(std::move(s))
		{
		}
		claim(const date& s)
		    : val(int64_t(std::chrono::system_clock::to_time_t(s)))
		{
		}
		claim(const std::set<std::string>& s)
		    : val(picojson::array(s.cbegin(), s.cend()))
		{
		}
		claim(const picojson::value& val)
		    : val(val)
		{
		}
#endif

		/**
		 * Get wrapped json object
		 * \return Wrapped json object
		 */
		picojson::value to_json() const
		{
			return val;
		}

		/**
		 * Get type of contained object
		 * \return Type
		 */
		result_t<type> get_type() const
		{
			if (val.is<picojson::null>())
				return {type::null, JwtErrc::NoError};
			else if (val.is<bool>())
				return {type::boolean, JwtErrc::NoError};
			else if (val.is<int64_t>())
				return {type::int64, JwtErrc::NoError};
			else if (val.is<double>())
				return {type::number, JwtErrc::NoError};
			else if (val.is<std::string>())
				return {type::string, JwtErrc::NoError};
			else if (val.is<picojson::array>())
				return {type::array, JwtErrc::NoError};
			else if (val.is<picojson::object>())
				return {type::object, JwtErrc::NoError};
			else
				return {type::null, JwtErrc::InternalError};
		}

		/**
		 * Get the contained object as a string
		 * \return content as string
		 */
		result_t<const std::string&> as_string() const
		{
			if (!val.is<std::string>())
				return {"", JwtErrc::BadCastError};
			return {val.get<std::string>(), JwtErrc::NoError};
		}
		/**
		 * Get the contained object as a date
		 * \return content as date
		 */
		result_t<const date> as_date() const
		{
			auto i = as_int();
			if (i.second != JwtErrc::NoError)
			{
				return {date(), i.second};
			}
			return {std::chrono::system_clock::from_time_t(i.first), JwtErrc::NoError};
		}
		/**
		 * Get the contained object as an array
		 * \return content as array
		 */
		result_t<const picojson::array&> as_array() const
		{
			if (!val.is<picojson::array>())
				return {picojson::array(), JwtErrc::BadCastError};
			return {val.get<picojson::array>(), JwtErrc::NoError};
		}
		/**
		 * Get the contained object as a set of strings
		 * \return content as set of strings
		 */
		result_t<const std::set<std::string>> as_set() const
		{
			result_t<std::set<std::string>> res;
			result_t<const picojson::array&> array_res = as_array();
			if (array_res.second != JwtErrc::NoError)
			{
				res.second = array_res.second;
				return res;
			}
			for (auto& e : array_res.first)
			{
				if (!e.is<std::string>())
					return {res.first, JwtErrc::BadCastError};
				res.first.insert(e.get<std::string>());
			}
			return res;
		}
		/**
		 * Get the contained object as an integer
		 * \return content as int
		 */
		result_t<int64_t> as_int() const
		{
			result_t<int64_t> res;
			if (!val.is<int64_t>())
				return {0, JwtErrc::BadCastError};
			return {val.get<int64_t>(), JwtErrc::NoError};
		}
		/**
		 * Get the contained object as a bool
		 * \return content as bool
		 */
		result_t<bool> as_bool() const
		{
			if (!val.is<bool>())
				return {false, JwtErrc::BadCastError};
			return {val.get<bool>(), JwtErrc::NoError};
		}
		/**
		 * Get the contained object as a number
		 * \return content as double
		 */
		result_t<double> as_number() const
		{
			if (!val.is<double>())
				return {0.0, JwtErrc::BadCastError};
			return {val.get<double>(), JwtErrc::NoError};
		}
		result_t<const picojson::object&> as_object() const
		{
			if (!val.is<picojson::object>())
				return {picojson::object(), JwtErrc::BadCastError};
			return {val.get<picojson::object>(), JwtErrc::NoError};
		}
	};

	/**
	 * Base class that represents a token payload.
	 * Contains Convenience accessors for common claims.
	 */
	class payload
	{
	protected:
		std::unordered_map<std::string, claim> payload_claims;

	public:
		/**
		 * Check if issuer is present ("iss")
		 * \return true if present, false otherwise
		 */
		bool has_issuer() const noexcept
		{
			return has_payload_claim("iss");
		}
		/**
		 * Check if subject is present ("sub")
		 * \return true if present, false otherwise
		 */
		bool has_subject() const noexcept
		{
			return has_payload_claim("sub");
		}
		/**
		 * Check if audience is present ("aud")
		 * \return true if present, false otherwise
		 */
		bool has_audience() const noexcept
		{
			return has_payload_claim("aud");
		}
		/**
		 * Check if expires is present ("exp")
		 * \return true if present, false otherwise
		 */
		bool has_expires_at() const noexcept
		{
			return has_payload_claim("exp");
		}
		/**
		 * Check if not before is present ("nbf")
		 * \return true if present, false otherwise
		 */
		bool has_not_before() const noexcept
		{
			return has_payload_claim("nbf");
		}
		/**
		 * Check if issued at is present ("iat")
		 * \return true if present, false otherwise
		 */
		bool has_issued_at() const noexcept
		{
			return has_payload_claim("iat");
		}
		/**
		 * Check if token id is present ("jti")
		 * \return true if present, false otherwise
		 */
		bool has_id() const noexcept
		{
			return has_payload_claim("jti");
		}
		/**
		 * Get issuer claim
		 * \return issuer as string
		 */
		result_t<const std::string&> get_issuer() const
		{
			auto claim = get_payload_claim("iss");
			if (claim.second != JwtErrc::NoError)
			{
				return {std::string(), claim.second};
			}
			auto to_string = claim.first.as_string();
			if (to_string.second != JwtErrc::NoError)
			{
				return {std::string(), to_string.second};
			}
			return {to_string.first, JwtErrc::NoError};
		}
		/**
		 * Get subject claim
		 * \return subject as string
		 */
		result_t<const std::string&> get_subject() const
		{
			auto claim = get_payload_claim("sub");
			if (claim.second != JwtErrc::NoError)
			{
				return {std::string(), claim.second};
			}
			auto to_string = claim.first.as_string();
			if (to_string.second != JwtErrc::NoError)
			{
				return {std::string(), to_string.second};
			}
			return {to_string.first, JwtErrc::NoError};
		}
		/**
		 * Get audience claim
		 * \return audience as a set of strings
		 */
		result_t<std::set<std::string>> get_audience() const
		{
			auto claim = get_payload_claim("aud");
			if (claim.second != JwtErrc::NoError)
			{
				return {std::set<std::string>(), claim.second};
			}
			auto to_set = claim.first.as_set();
			if (to_set.second != JwtErrc::NoError)
			{
				return {std::set<std::string>(), to_set.second};
			}
			return {to_set.first, JwtErrc::NoError};
		}
		/**
		 * Get expires claim
		 * \return expires as a date in utc
		 */
		result_t<const date> get_expires_at() const
		{
			auto claim = get_payload_claim("exp");
			if (claim.second != JwtErrc::NoError)
			{
				return {date(), claim.second};
			}
			auto to_date = claim.first.as_date();
			if (to_date.second != JwtErrc::NoError)
			{
				return {date(), to_date.second};
			}
			return {to_date.first, JwtErrc::NoError};
		}
		/**
		 * Get not valid before claim
		 * \return nbf date in utc
		 */
		result_t<const date> get_not_before() const
		{
			auto claim = get_payload_claim("nbf");
			if (claim.second != JwtErrc::NoError)
			{
				return {date(), claim.second};
			}
			auto to_date = claim.first.as_date();
			if (to_date.second != JwtErrc::NoError)
			{
				return {date(), to_date.second};
			}
			return {to_date.first, JwtErrc::NoError};
		}
		/**
		 * Get issued at claim
		 * \return issued at as date in utc
		 */
		result_t<const date> get_issued_at() const
		{
			auto claim = get_payload_claim("iat");
			if (claim.second != JwtErrc::NoError)
			{
				return {date(), claim.second};
			}
			auto to_date = claim.first.as_date();
			if (to_date.second != JwtErrc::NoError)
			{
				return {date(), to_date.second};
			}
			return {to_date.first, JwtErrc::NoError};
		}
		/**
		 * Get id claim
		 * \return id as string
		 */
		result_t<const std::string&> get_id() const
		{
			auto claim = get_payload_claim("jti");
			if (claim.second != JwtErrc::NoError)
			{
				return {std::string(), claim.second};
			}
			auto to_string = claim.first.as_string();
			if (to_string.second != JwtErrc::NoError)
			{
				return {std::string(), to_string.second};
			}
			return {to_string.first, JwtErrc::NoError};
		}
		/**
		 * Check if a payload claim is present
		 * \return true if claim was present, false otherwise
		 */
		bool has_payload_claim(const std::string& name) const noexcept
		{
			return payload_claims.count(name) != 0;
		}
		/**
		 * Get payload claim
		 * \return Requested claim
		 */
		result_t<const claim&> get_payload_claim(const std::string& name) const
		{
			if (!has_payload_claim(name))
				return {claim(), JwtErrc::ClaimNotFound};
			return {payload_claims.at(name), JwtErrc::NoError};
		}
		/**
		 * Get all payload claims
		 * \return map of claims
		 */
		std::unordered_map<std::string, claim> get_payload_claims() const
		{
			return payload_claims;
		}
	};

	/**
	 * Base class that represents a token header.
	 * Contains Convenience accessors for common claims.
	 */
	class header
	{
	protected:
		std::unordered_map<std::string, claim> header_claims;

	public:
		/**
		 * Check if algortihm is present ("alg")
		 * \return true if present, false otherwise
		 */
		bool has_algorithm() const noexcept
		{
			return has_header_claim("alg");
		}
		/**
		 * Check if type is present ("typ")
		 * \return true if present, false otherwise
		 */
		bool has_type() const noexcept
		{
			return has_header_claim("typ");
		}
		/**
		 * Check if content type is present ("cty")
		 * \return true if present, false otherwise
		 */
		bool has_content_type() const noexcept
		{
			return has_header_claim("cty");
		}
		/**
		 * Check if key id is present ("kid")
		 * \return true if present, false otherwise
		 */
		bool has_key_id() const noexcept
		{
			return has_header_claim("kid");
		}
		/**
		 * Get algorithm claim
		 * \return algorithm as string
		 */
		result_t<const std::string&> get_algorithm() const
		{
			auto claim = get_header_claim("alg");
			if (claim.second != JwtErrc::NoError)
			{
				return {std::string(), claim.second};
			}
			auto to_string = claim.first.as_string();
			if (to_string.second != JwtErrc::NoError)
			{
				return {std::string(), to_string.second};
			}
			return {to_string.first, JwtErrc::NoError};
		}
		/**
		 * Get type claim
		 * \return type as a string
		 */
		result_t<const std::string&> get_type() const
		{
			auto claim = get_header_claim("typ");
			if (claim.second != JwtErrc::NoError)
			{
				return {std::string(), claim.second};
			}
			auto to_string = claim.first.as_string();
			if (to_string.second != JwtErrc::NoError)
			{
				return {std::string(), to_string.second};
			}
			return {to_string.first, JwtErrc::NoError};
		}
		/**
		 * Get content type claim
		 * \return content type as string
		 */
		result_t<const std::string&> get_content_type() const
		{
			auto claim = get_header_claim("cty");
			if (claim.second != JwtErrc::NoError)
			{
				return {std::string(), claim.second};
			}
			auto to_string = claim.first.as_string();
			if (to_string.second != JwtErrc::NoError)
			{
				return {std::string(), to_string.second};
			}
			return {to_string.first, JwtErrc::NoError};
		}
		/**
		 * Get key id claim
		 * \return key id as string
		 */
		result_t<const std::string&> get_key_id() const
		{
			auto claim = get_header_claim("kid");
			if (claim.second != JwtErrc::NoError)
			{
				return {std::string(), claim.second};
			}
			auto to_string = claim.first.as_string();
			if (to_string.second != JwtErrc::NoError)
			{
				return {std::string(), to_string.second};
			}
			return {to_string.first, JwtErrc::NoError};
		}
		/**
		 * Check if a header claim is present
		 * \return true if claim was present, false otherwise
		 */
		bool has_header_claim(const std::string& name) const noexcept
		{
			return header_claims.count(name) != 0;
		}
		/**
		 * Get header claim
		 * \return Requested claim
		 */
		result_t<const claim&> get_header_claim(const std::string& name) const
		{
			if (!has_header_claim(name))
				return {claim(), JwtErrc::ClaimNotFound};
			return {header_claims.at(name), JwtErrc::NoError};
		}
		/**
		 * Get all header claims
		 * \return map of claims
		 */
		std::unordered_map<std::string, claim> get_header_claims() const
		{
			return header_claims;
		}
	};

	/**
	 * Class containing all information about a decoded token
	 */
	class decoded_jwt : public header, public payload
	{
	protected:
		/// Unmodifed token, as passed to constructor
		const std::string token;
		/// Header part decoded from base64
		std::string header;
		/// Unmodified header part in base64
		std::string header_base64;
		/// Payload part decoded from base64
		std::string payload;
		/// Unmodified payload part in base64
		std::string payload_base64;
		/// Signature part decoded from base64
		std::string signature;
		/// Unmodified signature part in base64
		std::string signature_base64;
		/// Error code
		JwtErrc construct_error_code;

	public:
		/**
		 * Constructor
		 * Parses a given token
		 * \param token The token to parse
		 */
		explicit decoded_jwt(const std::string& token)
		    : token(token)
		    , construct_error_code(JwtErrc::NoError)
		{
			do
			{
				auto hdr_end = token.find('.');
				if (hdr_end == std::string::npos)
				{
					assert(0);
					construct_error_code = JwtErrc::TokenInvalidSuppliedError;
					break;
				}

				auto payload_end = token.find('.', hdr_end + 1);
				if (payload_end == std::string::npos)
				{
					assert(0);
					construct_error_code = JwtErrc::TokenInvalidSuppliedError;
					break;
				}

				header = header_base64 = token.substr(0, hdr_end);
				payload = payload_base64 = token.substr(hdr_end + 1, payload_end - hdr_end - 1);
				signature = signature_base64 = token.substr(payload_end + 1);

				// Fix padding: JWT requires padding to get removed
				auto fix_padding = [](std::string& str) {
					switch (str.size() % 4)
					{
						case 1:
							str += alphabet::base64url::fill();
#ifdef __cpp_attributes
#if __has_cpp_attribute(fallthrough)
							[[fallthrough]];
#endif
#endif
						case 2:
							str += alphabet::base64url::fill();
#ifdef __cpp_attributes
#if __has_cpp_attribute(fallthrough)
							[[fallthrough]];
#endif
#endif
						case 3:
							str += alphabet::base64url::fill();
#ifdef __cpp_attributes
#if __has_cpp_attribute(fallthrough)
							[[fallthrough]];
#endif
#endif
						default:
							break;
					}
				};

				fix_padding(header);
				fix_padding(payload);
				fix_padding(signature);

				result_t<std::string> decoded;
				decoded = base::decode<alphabet::base64url>(header);
				if (decoded.second != JwtErrc::NoError)
				{
					assert(0);
					construct_error_code = JwtErrc::DecodeError;
					break;
				}
				header = decoded.first;

				decoded = base::decode<alphabet::base64url>(payload);
				if (decoded.second != JwtErrc::NoError)
				{
					assert(0);
					construct_error_code = JwtErrc::DecodeError;
					break;
				}
				payload = decoded.first;

				decoded = base::decode<alphabet::base64url>(signature);
				if (decoded.second != JwtErrc::NoError)
				{
					assert(0);
					construct_error_code = JwtErrc::DecodeError;
					break;
				}
				signature = decoded.first;

				auto parse_claims = [](const std::string& str) -> result_t<std::unordered_map<std::string, claim>> {
					result_t<std::unordered_map<std::string, claim>> res;
					picojson::value val;
					if (!picojson::parse(val, str).empty())
					{
						res.second = JwtErrc::ParseError;
						return res;
					}

					for (auto& e : val.get<picojson::object>())
					{
						res.first.insert({e.first, claim(e.second)});
					}

					return res;
				};

				result_t<std::unordered_map<std::string, claim>> parsed = parse_claims(header);
				if (parsed.second != JwtErrc::NoError)
				{
					assert(0);
					construct_error_code = parsed.second;
					break;
				}
				header_claims = parsed.first;

				parsed = parse_claims(payload);
				if (parsed.second != JwtErrc::NoError)
				{
					assert(0);
					construct_error_code = parsed.second;
					break;
				}
				payload_claims = parsed.first;
			} while (0);
		}
		/**
		 * Get token string, as passed to constructor
		 * \return token as passed to constructor
		 */
		const std::string& get_token() const
		{
			return token;
		}
		/**
		 * Get header part as json string
		 * \return header part after base64 decoding
		 */
		const std::string& get_header() const
		{
			return header;
		}
		/**
		 * Get payload part as json string
		 * \return payload part after base64 decoding
		 */
		const std::string& get_payload() const
		{
			return payload;
		}
		/**
		 * Get signature part as json string
		 * \return signature part after base64 decoding
		 */
		const std::string& get_signature() const
		{
			return signature;
		}
		/**
		 * Get header part as base64 string
		 * \return header part before base64 decoding
		 */
		const std::string& get_header_base64() const
		{
			return header_base64;
		}
		/**
		 * Get payload part as base64 string
		 * \return payload part before base64 decoding
		 */
		const std::string& get_payload_base64() const
		{
			return payload_base64;
		}
		/**
		 * Get signature part as base64 string
		 * \return signature part before base64 decoding
		 */
		const std::string& get_signature_base64() const
		{
			return signature_base64;
		}
		JwtErrc error() const
		{
			return construct_error_code;
		}
	};
	/**
	 * Builder class to build and sign a new token
	 * Use jwt::create() to get an instance of this class.
	 */
	class builder
	{
		std::unordered_map<std::string, claim> header_claims;
		std::unordered_map<std::string, claim> payload_claims;

		builder() {}
		friend builder create();

	public:
		/**
		 * Set a header claim.
		 * \param id Name of the claim
		 * \param c Claim to add
		 * \return *this to allow for method chaining
		 */
		builder& set_header_claim(const std::string& id, claim c)
		{
			header_claims[id] = std::move(c);
			return *this;
		}
		/**
		 * Set a payload claim.
		 * \param id Name of the claim
		 * \param c Claim to add
		 * \return *this to allow for method chaining
		 */
		builder& set_payload_claim(const std::string& id, claim c)
		{
			payload_claims[id] = std::move(c);
			return *this;
		}
		/**
		 * Set algorithm claim
		 * You normally don't need to do this, as the algorithm is automatically set if you don't change it.
		 * \param str Name of algorithm
		 * \return *this to allow for method chaining
		 */
		builder& set_algorithm(const std::string& str)
		{
			return set_header_claim("alg", claim(str));
		}
		/**
		 * Set type claim
		 * \param str Type to set
		 * \return *this to allow for method chaining
		 */
		builder& set_type(const std::string& str)
		{
			return set_header_claim("typ", claim(str));
		}
		/**
		 * Set content type claim
		 * \param str Type to set
		 * \return *this to allow for method chaining
		 */
		builder& set_content_type(const std::string& str)
		{
			return set_header_claim("cty", claim(str));
		}
		/**
		 * Set key id claim
		 * \param str Key id to set
		 * \return *this to allow for method chaining
		 */
		builder& set_key_id(const std::string& str)
		{
			return set_header_claim("kid", claim(str));
		}
		/**
		 * Set issuer claim
		 * \param str Issuer to set
		 * \return *this to allow for method chaining
		 */
		builder& set_issuer(const std::string& str)
		{
			return set_payload_claim("iss", claim(str));
		}
		/**
		 * Set subject claim
		 * \param str Subject to set
		 * \return *this to allow for method chaining
		 */
		builder& set_subject(const std::string& str)
		{
			return set_payload_claim("sub", claim(str));
		}
		/**
		 * Set audience claim
		 * \param l Audience set
		 * \return *this to allow for method chaining
		 */
		builder& set_audience(const std::set<std::string>& l)
		{
			return set_payload_claim("aud", claim(l));
		}
		/**
		 * Set expires at claim
		 * \param d Expires time
		 * \return *this to allow for method chaining
		 */
		builder& set_expires_at(const date& d)
		{
			return set_payload_claim("exp", claim(d));
		}
		/**
		 * Set not before claim
		 * \param d First valid time
		 * \return *this to allow for method chaining
		 */
		builder& set_not_before(const date& d)
		{
			return set_payload_claim("nbf", claim(d));
		}
		/**
		 * Set issued at claim
		 * \param d Issued at time, should be current time
		 * \return *this to allow for method chaining
		 */
		builder& set_issued_at(const date& d)
		{
			return set_payload_claim("iat", claim(d));
		}
		/**
		 * Set id claim
		 * \param str ID to set
		 * \return *this to allow for method chaining
		 */
		builder& set_id(const std::string& str)
		{
			return set_payload_claim("jti", claim(str));
		}

		/**
		 * Sign token and return result
		 * \param algo Instance of an algorithm to sign the token with
		 * \return Final token as a string
		 */
		template <typename T>
		result_t<std::string> sign(const T& algo)
		{
			this->set_algorithm(algo.name());

			picojson::object obj_header;
			for (auto& e : header_claims)
			{
				obj_header.insert({e.first, e.second.to_json()});
			}
			picojson::object obj_payload;
			for (auto& e : payload_claims)
			{
				obj_payload.insert({e.first, e.second.to_json()});
			}

			auto encode = [](const std::string& data) -> result_t<std::string> {
				result_t<std::string> base = base::encode<alphabet::base64url>(data);
				if (base.second != JwtErrc::NoError)
				{
					return base;
				}
				auto pos = base.first.find(alphabet::base64url::fill());
				return {base.first.substr(0, pos), JwtErrc::NoError};
			};

			result_t<std::string> header = encode(picojson::value(obj_header).serialize());
			if (header.second != JwtErrc::NoError)
			{
				return header;
			}

			result_t<std::string> payload = encode(picojson::value(obj_payload).serialize());
			if (payload.second != JwtErrc::NoError)
			{
				return payload;
			}

			std::string token = header.first + "." + payload.first;

			result_t<std::string> sign = algo.sign(token);
			if (sign.second != JwtErrc::NoError)
			{
				return sign;
			}

			result_t<std::string> sign_enc = encode(sign.first);
			if (sign_enc.second != JwtErrc::NoError)
			{
				return sign_enc;
			}

			return {token + "." + sign_enc.first, JwtErrc::NoError};
		}
	};

	/**
	 * Verifier class used to check if a decoded token contains all claims required by your application and has a valid
	 * signature.
	 */
	template <typename Clock>
	class verifier
	{
		struct algo_base
		{
			virtual ~algo_base() = default;
			virtual JwtErrc verify(const std::string& data, const std::string& sig) = 0;
		};
		template <typename T>
		struct algo : public algo_base
		{
			T alg;
			explicit algo(T a)
			    : alg(a)
			{
			}
			virtual JwtErrc verify(const std::string& data, const std::string& sig) override
			{
				return alg.verify(data, sig);
			}
		};

		/// Required claims
		std::unordered_map<std::string, claim> claims;
		/// Leeway time for exp, nbf and iat
		size_t default_leeway = 0;
		/// Instance of clock type
		Clock clock;
		/// Supported algorithms
		std::unordered_map<std::string, std::shared_ptr<algo_base>> algs;

	public:
		/**
		 * Constructor for building a new verifier instance
		 * \param c Clock instance
		 */
		explicit verifier(Clock c)
		    : clock(c)
		{
		}

		/**
		 * Set default leeway to use.
		 * \param leeway Default leeway to use if not specified otherwise
		 * \return *this to allow chaining
		 */
		verifier& leeway(size_t leeway)
		{
			default_leeway = leeway;
			return *this;
		}
		/**
		 * Set leeway for expires at.
		 * If not specified the default leeway will be used.
		 * \param leeway Set leeway to use for expires at.
		 * \return *this to allow chaining
		 */
		verifier& expires_at_leeway(size_t leeway)
		{
			return with_claim("exp", claim(std::chrono::system_clock::from_time_t(leeway)));
		}
		/**
		 * Set leeway for not before.
		 * If not specified the default leeway will be used.
		 * \param leeway Set leeway to use for not before.
		 * \return *this to allow chaining
		 */
		verifier& not_before_leeway(size_t leeway)
		{
			return with_claim("nbf", claim(std::chrono::system_clock::from_time_t(leeway)));
		}
		/**
		 * Set leeway for issued at.
		 * If not specified the default leeway will be used.
		 * \param leeway Set leeway to use for issued at.
		 * \return *this to allow chaining
		 */
		verifier& issued_at_leeway(size_t leeway)
		{
			return with_claim("iat", claim(std::chrono::system_clock::from_time_t(leeway)));
		}
		/**
		 * Set an issuer to check for.
		 * Check is casesensitive.
		 * \param iss Issuer to check for.
		 * \return *this to allow chaining
		 */
		verifier& with_issuer(const std::string& iss)
		{
			return with_claim("iss", claim(iss));
		}
		/**
		 * Set a subject to check for.
		 * Check is casesensitive.
		 * \param sub Subject to check for.
		 * \return *this to allow chaining
		 */
		verifier& with_subject(const std::string& sub)
		{
			return with_claim("sub", claim(sub));
		}
		/**
		 * Set an audience to check for.
		 * If any of the specified audiences is not present in the token the check fails.
		 * \param aud Audience to check for.
		 * \return *this to allow chaining
		 */
		verifier& with_audience(const std::set<std::string>& aud)
		{
			return with_claim("aud", claim(aud));
		}
		/**
		 * Set an id to check for.
		 * Check is casesensitive.
		 * \param id ID to check for.
		 * \return *this to allow chaining
		 */
		verifier& with_id(const std::string& id)
		{
			return with_claim("jti", claim(id));
		}
		/**
		 * Specify a claim to check for.
		 * \param name Name of the claim to check for
		 * \param c Claim to check for
		 * \return *this to allow chaining
		 */
		verifier& with_claim(const std::string& name, claim c)
		{
			claims[name] = c;
			return *this;
		}

		/**
		 * Add an algorithm available for checking.
		 * \param alg Algorithm to allow
		 * \return *this to allow chaining
		 */
		template <typename Algorithm>
		verifier& allow_algorithm(Algorithm alg)
		{
			algs[alg.name()] = std::make_shared<algo<Algorithm>>(alg);
			return *this;
		}

		/**
		 * Verify the given token.
		 * \param jwt Token to check
		 */
		JwtErrc verify(const decoded_jwt& jwt) const
		{
			const std::string data = jwt.get_header_base64() + "." + jwt.get_payload_base64();
			const std::string sig = jwt.get_signature();
			result_t<const std::string&> algo = jwt.get_algorithm();
			if ((algo.second != JwtErrc::NoError) || (algs.count(algo.first) == 0))
				return JwtErrc::WrongAlgorithmError;
			JwtErrc verify_result = algs.at(algo.first)->verify(data, sig);
			if (verify_result != JwtErrc::NoError)
				return verify_result;

			auto assert_claim_eq = [](const decoded_jwt& jwt, const std::string& key, const claim& c) {
				if (!jwt.has_payload_claim(key))
					return JwtErrc::DecodedJwtMissingError;
				auto jc = jwt.get_payload_claim(key);
				if (jc.second != JwtErrc::NoError)
					return jc.second;
				auto jc_type = jc.first.get_type();
				if (jc_type.second != JwtErrc::NoError)
					return jc_type.second;
				auto c_type = c.get_type();
				if (c_type.second != JwtErrc::NoError)
					return c_type.second;
				if (jc_type.first != c_type.first)
					return JwtErrc::ClaimTypeKeyMismatchError;
				if (c_type.first == claim::type::int64)
				{
					auto c_date = c.as_date();
					if (c_date.second != JwtErrc::NoError)
						return c_date.second;
					auto jc_date = jc.first.as_date();
					if (jc_date.second != JwtErrc::NoError)
						return jc_date.second;
					if (c_date.first != jc_date.first)
						return JwtErrc::ClaimKeyDoesNotMatchExpectedError;
				}
				else if (c_type.first == claim::type::array)
				{
					auto s1 = c.as_set();
					if (s1.second != JwtErrc::NoError)
						return s1.second;
					auto s2 = jc.first.as_set();
					if (s2.second != JwtErrc::NoError)
						return s2.second;
					if (s1.first.size() != s2.first.size())
						return JwtErrc::ClaimKeyDoesNotMatchExpectedError;
					auto it1 = s1.first.cbegin();
					auto it2 = s2.first.cbegin();
					while (it1 != s1.first.cend() && it2 != s2.first.cend())
					{
						if (*it1++ != *it2++)
							return JwtErrc::ClaimKeyDoesNotMatchExpectedError;
					}
				}
				else if (c_type.first == claim::type::string)
				{
					auto c_string = c.as_string();
					if (c_string.second != JwtErrc::NoError)
						return c_string.second;
					auto jc_string = jc.first.as_string();
					if (jc_string.second != JwtErrc::NoError)
						return jc_string.second;
					if (c_string.first != jc_string.first)
						return JwtErrc::ClaimKeyDoesNotMatchExpectedError;
				}
				else
					return JwtErrc::ClaimKeyDoesNotMatchExpectedError;
				return JwtErrc::NoError;
			};

			auto time = clock.now();

			if (jwt.has_expires_at())
			{
				result_t<const date> the_date = claims.at("exp").as_date();
				if (the_date.second != JwtErrc::NoError)
					return the_date.second;
				auto leeway =
				    claims.count("exp") == 1 ? std::chrono::system_clock::to_time_t(the_date.first) : default_leeway;
				auto exp = jwt.get_expires_at();
				if (exp.second != JwtErrc::NoError)
					return exp.second;
				if (time > exp.first + std::chrono::seconds(leeway))
					return JwtErrc::TokenExpiredError;
			}
			if (jwt.has_issued_at())
			{
				result_t<const date> the_date = claims.at("iat").as_date();
				if (the_date.second != JwtErrc::NoError)
					return the_date.second;
				auto leeway =
				    claims.count("iat") == 1 ? std::chrono::system_clock::to_time_t(the_date.first) : default_leeway;
				auto iat = jwt.get_issued_at();
				if (iat.second != JwtErrc::NoError)
					return iat.second;
				if (time < iat.first - std::chrono::seconds(leeway))
					return JwtErrc::TokenExpiredError;
			}
			if (jwt.has_not_before())
			{
				result_t<const date> the_date = claims.at("nbf").as_date();
				if (the_date.second != JwtErrc::NoError)
					return the_date.second;
				auto leeway =
				    claims.count("nbf") == 1 ? std::chrono::system_clock::to_time_t(the_date.first) : default_leeway;
				auto nbf = jwt.get_not_before();
				if (nbf.second != JwtErrc::NoError)
					return nbf.second;
				if (time < nbf.first - std::chrono::seconds(leeway))
					return JwtErrc::TokenExpiredError;
			}
			for (auto& c : claims)
			{
				if (c.first == "exp" || c.first == "iat" || c.first == "nbf")
				{
					// Nothing to do here, already checked
				}
				else if (c.first == "aud")
				{
					if (!jwt.has_audience())
						return JwtErrc::TokenRequiredAudienceError;
					auto aud = jwt.get_audience();
					if (aud.second != JwtErrc::NoError)
						return aud.second;
					auto expected = c.second.as_set();
					if (expected.second != JwtErrc::NoError)
						return expected.second;
					for (auto& e : expected.first)
						if (aud.first.count(e) == 0)
							return JwtErrc::TokenRequiredAudienceError;
				}
				else
				{
					return assert_claim_eq(jwt, c.first, c.second);
				}
			}

			return JwtErrc::NoError;
		}
	};

	/**
	 * Create a verifier using the given clock
	 * \param c Clock instance to use
	 * \return verifier instance
	 */
	template <typename Clock>
	verifier<Clock> verify(Clock c)
	{
		return verifier<Clock>(c);
	}

	/**
	 * Default clock class using std::chrono::system_clock as a backend.
	 */
	struct default_clock
	{
		std::chrono::system_clock::time_point now() const
		{
			return std::chrono::system_clock::now();
		}
	};

	/**
	 * Create a verifier using the default clock
	 * \return verifier instance
	 */
	inline verifier<default_clock> verify()
	{
		return verify<default_clock>({});
	}

	/**
	 * Return a builder instance to create a new token
	 */
	inline builder create()
	{
		return builder();
	}

	/**
	 * Decode a token
	 * \param token Token to decode
	 * \return Decoded token
	 */
	inline decoded_jwt decode(const std::string& token)
	{
		return decoded_jwt(token);
	}
} // namespace jwt
