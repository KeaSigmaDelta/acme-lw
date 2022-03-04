#include "acme-exception.h"

#include <openssl/err.h>
#include "json.hpp"

using namespace std;

namespace acme_lw
{

AcmeException::AcmeException(const string& message, const string& serverResponse)
{
    // We assume the error is going to be from openssl. If it's not, we just
    // use the string passed in as the error message.
    unsigned long err = ERR_get_error();
    while (ERR_get_error()); // clear any previous errors we didn't deal with for some reason;

    if (err)
    {
        constexpr int buffSize = 120;
        char buffer[buffSize];
        ERR_error_string(err, buffer);

        what_ = (message.size() ? message + ": " : message) + "OpenSSL error (" + to_string(err) + "): " + buffer;
    }
    else
    {
        what_ = message;
    }
    
    serverResponse_ = serverResponse;
    
    if(serverResponse_.length() > 0)
    {
        try {
            auto json = nlohmann::json::parse(serverResponse_);
            errorType_ = json.at("type");
            errorDetail_ = json.at("detail");
        } 
        catch(...)
        {
            ; // Silently ignore because the exception means that it wasn't a proper json response
        }
    }
}

const char * AcmeException::what() const noexcept
{
    return  what_.c_str();
}

const std::string& AcmeException::getServerResponse() const
{
    return serverResponse_;
}

const std::string& AcmeException::getErrorType() const
{
    return errorType_;
}

const std::string& AcmeException::getErrorDetail() const
{
    return errorDetail_;
}

}
