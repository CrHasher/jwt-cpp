#pragma once

#ifndef CPP_JWT_ERROR_CODES_HPP
#define CPP_JWT_ERROR_CODES_HPP

#include <system_error>

namespace jwt
{
	// For simplicity all error codes are aggregated to one category, they could be separated but I see no reason to do
	// that in this case because we have too few errors and they repeat
	enum class JwtErrc
	{
		NoError = 0,
		InternalError,
		BadCastError,
		DecodeError,
		ParseError,
		DecodedJwtMissingError,
		ClaimTypeKeyMismatchError,
		ClaimKeyDoesNotMatchExpectedError,
		WrongAlgorithmError,
		FailedToLoadKeyInvalidError,
		FailedToLoadPrivateKeyBioWriteError,
		FailedToLoadPrivateKeyEvpPKeyAssignRsaError,
		FailedToLoadPrivateKeyPemReadBioError,
		FailedToLoadPublicKeyBioWriteError,
		FailedToLoadPublicKeyPemReadBioError,
		InvalidInputError,
		SignatureCreationContextCreationError,
		SignatureCreationRSAPaddingAddError,
		SignatureCreationRSAPrivateEncryptError,
		SignatureCreationSignInitError,
		SignatureGenerationEVPDigestFinalError,
		SignatureGenerationEVPDigestInitError,
		SignatureGenerationEVPDigestUpdateError,
		SignatureGenerationError,
		SignatureInvalidError,
		SignatureVerificationContextCreationError,
		SignatureVerificationError,
		SignatureVerificationVerifyInitError,
		SignatureVerificationVerifyUpdateError,
		TokenVerificationError,
		TokenExpiredError,
		TokenInvalidSuppliedError,
		TokenRequiredAudienceError,
		ClaimNotFound,
	};

	std::error_code make_error_code(JwtErrc err);
} // namespace jwt

namespace std
{
	template <>
	struct is_error_code_enum<jwt::JwtErrc> : true_type
	{
	};
} // namespace std

namespace jwt
{
	// anon namespace
	namespace
	{
		struct JwtErrCategory : std::error_category
		{
			const char* name() const noexcept override
			{
				return "jwt";
			}

			std::string message(int ev) const override
			{
				switch (static_cast<JwtErrc>(ev))
				{
					case JwtErrc::NoError:
						return "no error";
				};
				return "unknown decode error";
				assert(0 && "Code not reached");
			}
		};

		const JwtErrCategory theJwtErrCategory{};
	} // namespace

	inline std::error_code make_error_code(JwtErrc err)
	{
		return {static_cast<int>(err), theJwtErrCategory};
	}
} // namespace jwt

namespace jwt
{
	template <typename T> using result_t = std::pair<T, JwtErrc>; // convenience result type
}

#endif
