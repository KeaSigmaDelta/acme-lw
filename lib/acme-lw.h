#pragma once

#include "acme-exception.h"

#include <ctime>
#include <functional>
#include <list>
#include <memory>


namespace acme_lw
{

struct Certificate
{
    std::string fullchain;
    std::string privkey;

    // Note that neither of the 'Expiry' calls below require 'privkey'
    // to be set; they only rely on 'fullchain'.

    /**
        Returns the number of seconds since 1970, i.e., epoch time.

        Due to openssl quirkiness on older versions (< 1.1.1?) there 
        might be a little drift from a strictly accurate result, but 
        it will be close enough for the purpose of determining 
        whether the certificate needs to be renewed.
    */
    ::time_t getExpiry() const;

    /**
        Returns the 'Not After' result that openssl would display if
        running the following command.

            openssl x509 -noout -in fullchain.pem -text

        For example:

            May  6 21:15:03 2018 GMT
    */
    std::string getExpiryDisplay() const;
};

struct AcmeClientImpl;

class AcmeClient
{
public:
    /**
        Creates a new AcmeClient that connects to the ACME server identified by directoryUrl.

        @param directoryUrl the Certificate Authority's (CA's) ACME server directory URL. Defaults to 
        LetsEncrypt if empty
        
        @throws AcmeException if something went wrong
    */
    AcmeClient(const std::string &directoryUrl);

    ~AcmeClient();

    /**
        The implementation of this function allows Let's Encrypt to
        verify that the requestor has control of the domain name.

        The callback may be called once for each domain name in the
        'issueCertificate' call. The callback should do whatever is
        needed so that a GET on the 'url' returns the 'keyAuthorization',
        (which is what the Acme protocol calls the expected response.)

        Note that this function may not be called in cases where
        Let's Encrypt already believes the caller has control
        of the domain name.
    */
    typedef std::function<void(const std::string& domainName,
		const std::string& url, const std::string& keyAuthorization)> Callback;
    
    /**
        Setup an ACME account. This must be called before issueCertificate.

        The accountPrivateKey is the Acme account private key used to sign
        requests to the acme CA, in pem format.

        IMPORTANT: Creating a new account will automatically accept the certificate authority's
        Terms-Of-Service (TOS). It is your responsibility to ask the user to read and accept prior
        to account creation. The static function getTermsOfServiceUrl() can be used to get the TOS.
        
        @param accountPrivateKey the private key for the ACME account
        @param allowCreateNew set to true to allow creation of a new account on the server. If 
        set to false, then it'll only retrieve an existing account, and will fail with an exception
        of type "urn:ietf:params:acme:error:accountDoesNotExist" (use e.getErrorType() to check)
        @param email optional contact email address (allows CA to contact you about your account/domains
        if needed)
        @param eabKID external account binding KID. Only needed with CAs that have an account to bind to
        @param eabHMAC external account binding HMAC. Only needed with CAs that have an account to bind to

        throws std::exception, usually an instance of acme_lw::AcmeException
    */
    void setupAccount(const std::string& accountPrivateKey, bool allowCreateNew, const std::string &email = "",
        const std::string &eabKID = "", const std::string &eabHMAC = "");

    /**
        Issue a certificate for the domainNames.
        The first one will be the 'Subject' (CN) in the certificate.
        
        IMPORTANT: You *MUST* call setupAccount() first.

        throws std::exception, usually an instance of acme_lw::AcmeException
    */
    Certificate issueCertificate(const std::list<std::string>& domainNames, Callback);
    
    /**
        Gets the terms of service URL.
    */
    const std::string& getTermsOfServiceUrl() const;

private:
    std::unique_ptr<AcmeClientImpl> impl_;
};

}
