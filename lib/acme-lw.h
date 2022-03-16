#pragma once

#include "acme-exception.h"

#include <ctime>
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
        The signingKey is the Acme account private key used to sign
        requests to the acme CA, in pem format.
        
        IMPORTANT: Creating a new account will automatically accept the certificate authority's
        Terms-Of-Service (TOS). It is your responsibility to ask the user to read and accept prior
        to account creation. The static function getTermsOfServiceUrl() can be used to get the TOS.
        
        @param signingKey the private key for the ACME account
        @param allowCreateNew set to true to allow creation of a new account on the server. If 
        set to false, then it'll only retrieve an existing account, and will fail with an exception
        of type "urn:ietf:params:acme:error:accountDoesNotExist" (use e.getErrorType() to check)
        @param email optional contact email address (allows CA to contact you about your account/domains
        if needed)
        @param eabKID external account binding KID. Only needed with CAs that have an account to bind to
        @param eabHMAC external account binding HMAC. Only needed with CAs that have an account to bind to
        
        @throws AcmeException if something went wrong
    */
    AcmeClient(const std::string& signingKey, bool allowCreateNew = true, const std::string &email = "",
        const std::string &eabKID = "", const std::string &eabHMAC = "");
    
    // ##### FIXME! ##### need a constructor to use when EAB credentials are needed

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
    typedef void (*Callback) (  const std::string& domainName,
                                const std::string& url,
                                const std::string& keyAuthorization);
    
    /**
        Sets up the ACME account. This either creates a new one, or retrieves an existing one.
        
        @param allowCreateNew set to true if you want to create a new account if there isn't 
        an existing one
        @param termsOfServiceAgreed must be set to true for account creation, or the server will
        reject it. 
        IMPORTANT: It's your responsibility to ask the user to agree to the certificate authority's
        Terms Of Service (TOS). 
        
        @return bool true if successful, and false if allowCreateNew was false and no account
        existed
        
        @throws AcmeException if something went wrong
    */
    bool setupAccount(bool allowCreateNew, bool termsOfServiceAgreed);

    /**
        Issue a certificate for the domainNames.
        The first one will be the 'Subject' (CN) in the certificate.
        
        IMPORTANT: You *MUST* call setupAcmeAccount first.

        throws std::exception, usually an instance of acme_lw::AcmeException
    */
    Certificate issueCertificate(const std::list<std::string>& domainNames, Callback);
    
    /**
        Gets the terms of service URL.
    */
    static const std::string& getTermsOfServiceUrl();
    
        /**
        Call once before instantiating AcmeClient.
        
        Note that this calls Let's Encrypt servers and so can throw
        if they're having issues.
        
        @param directoryUrl the ACME server's directory URL. Defaults to LetsEncrypt
        if left blank  
    */
    static void init(const std::string& directoryUrl = "");

    // Call once before application shutdown.
    static void teardown();

private:
    std::unique_ptr<AcmeClientImpl> impl_;
};

}
