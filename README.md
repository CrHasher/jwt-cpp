# jwt-cpp

An exception free header only library for creating and validating json web tokens in c++.

## Signature algorithms
As of version 0.2.0 jwt-cpp supports all algorithms defined by the spec. The modular design of jwt-cpp allows one to add additional algorithms without any problems. If you need any feel free to open a pull request.
For the sake of completeness, here is a list of all supported algorithms:
* HS256
* HS384
* HS512
* RS256
* RS384
* RS512
* ES256
* ES384
* ES512
* PS256
* PS384
* PS512

## Examples
Simple example of decoding a token:
```c++
#include <jwt-cpp/jwt.h>
#include <iostream>

int main(int argc, const char** argv) {
	//...
	std::string nsaID;
	jwt::decoded_jwt decodedNsaIDToken = jwt::decode(nsaIDToken, false);
	if (decodedNsaIDToken.error() == jwt::JwtErrc::NoError)
	{
		if (decodedNsaIDToken.has_payload_claim("sub"))
		{
			jwt::result_t<const jwt::claim&> sub = decodedNsaIDToken.get_payload_claim("sub");
			if (sub.second == jwt::JwtErrc::NoError)
			{
				jwt::result_t<std::string> subStr = sub.first.as_string();
				if (subStr.second == jwt::JwtErrc::NoError)
				{
					nsaID = subStr.first;
				}
			}
		}
	}
	//...
}
```

## Dependencies
In order to use jwt-cpp you need the following tools.
* libcrypto (openssl or compatible)
* a compiler supporting at least c++11
* basic stl support

