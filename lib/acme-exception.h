#pragma once

#include <exception>
#include <string>

namespace acme_lw
{

class AcmeException : public std::exception
{
public:
    AcmeException(const std::string &message, const std::string& serverResponse = "");

    virtual const char * what() const noexcept override;
    
    const std::string& getServerResponse() const;
    
    /**
        Returns the error type string returned by the server, or an empty string
        if this error is caused by something else (e.g., couldn't connect to server). 
    */
    const std::string& getErrorType() const;
    
    /**
        Returns the error detail returned by the server, or an empty string
        if this error is caused by something else (e.g., couldn't connect to server). 
    */
    const std::string& getErrorDetail() const;

private:
    std::string what_;
    
    std::string serverResponse_;
    std::string errorType_;
    std::string errorDetail_;
};

}
