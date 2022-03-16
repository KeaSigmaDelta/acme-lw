#include "acme-lw.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

#ifdef STD_FILESYSTEM
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

using namespace std;

namespace
{

string readFile(const string& fileName);
void   writeFile(const string& fileName, const string& contents);

void handleChallenge(const string& domain, const string& url, const string& keyAuthorization)
{
    cout << "To verify ownership of " << domain << " make\n\n"
            << "\t" << url << "\n\nrespond with this\n\n"
            << "\t" << keyAuthorization << "\n\n"
            << "Hit any key when done";

    getchar();
    cout << "\n***\n";
}

bool askUserAcceptTOS()
{
    cout << "You need to accept the Certificate Authority's Terms of Service. Read it at:" << endl
         << "\t" << acme_lw::AcmeClient::getTermsOfServiceUrl() << endl
         << "Type Y to accept, or N to reject, and press ENTER." << endl;
    char response = getchar();
    if(response == 'y' || response == 'Y') 
    {
        return true;
    } 
    else 
    {
        return false;
    }
}

}

int main(int argc, char * argv[])
{
#ifdef STAGING
    cout << "Running against staging environment.\n\n";
#endif

    if (argc < 3)
    {
        cout << "Usage is 'acme_lw_client [options] <file-name>, <domain-name>, <domain-name>, ...'\n"
                << "  * <file-name> holds the account private key in pem format\n"
                << "  * there must be at least one <domain-name>; the first will be the 'Subject' of the certificate\n"
                << "  * Options\n"
                << "    -email <email> - provide a contact email address so you can be contacted about your domain/account\n"
                << "    -eab_kid <kid> - optional External Account Binding (EAB) id (only needed with some providers)\n"
                << "    -eab_hmac <hmac> - optional EAB hmac value\n"
                << "    -zerossl - connect to ZeroSSL\n"
                << "    -letsencrypt - connect to LetsEncrypt (the default)\n";
        return 0;
    }
    
    std::string email, eabKID, eabHMAC, acmeUrl;
    
    int fileNameArgIdx = 1;
    for(int i = 1; i < argc; ++i) 
    {
        if(argv[i][0] != '-')
        {
            break;
        }
        if(strcmp(argv[i], "-email") == 0)
        {
            ++i;
            email = argv[i];
        } 
        else if(strcmp(argv[i], "-eab_kid") == 0)
        {
            ++i;
            eabKID = argv[i];
        } 
        else if(strcmp(argv[i], "-eab_hmac") == 0)
        {
            ++i;
            eabHMAC = argv[i];
        }
        else if(strcmp(argv[i], "-zerossl") == 0)
        {
            cout << "Connecting to ZeroSSL" << endl;
            acmeUrl = "https://acme.zerossl.com/v2/DV90";
        }
        else if(strcmp(argv[i], "-letsencrypt") == 0)
        {
            acmeUrl = "";
        }
        fileNameArgIdx = i + 1;
    }
    int domainArgIdx = fileNameArgIdx + 1;

    int exitStatus = 0;
    bool allowCreateNew = false;

    try
    {
        // Should be called once per process before a use of AcmeClient.
        acme_lw::AcmeClient::init(acmeUrl);
        
        string accountPrivateKey = readFile(argv[fileNameArgIdx]);
        
        bool retry = false;
        do
        {
            try
            {
                acme_lw::AcmeClient acmeClient(
                    accountPrivateKey, allowCreateNew, email, eabKID, eabHMAC);

                list<string> domainNames;
                for (int i = domainArgIdx; i < argc; ++i)
                {
                    domainNames.push_back(argv[i]);
                }
                
                acme_lw::Certificate certificate = acmeClient.issueCertificate(domainNames, handleChallenge);

                writeFile("fullchain.pem", certificate.fullchain);
                writeFile("privkey.pem", certificate.privkey);

                cout << "Files 'fullchain.pem' and 'privkey.pem' have been written to the current directory.\n";
                cout << "Certificate expires on " << certificate.getExpiryDisplay() << "\n";
            }
            catch(const acme_lw::AcmeException &e)
            {
                if(e.getErrorType().compare("urn:ietf:params:acme:error:accountDoesNotExist") == 0)
                {
                    if(askUserAcceptTOS())
                    {
                        cout << "Terms of service accepted. Creating account..." << endl;
                        allowCreateNew = true;
                        retry = true;
                    } 
                    else
                    {
                        cout << "Terms of service rejected. Exiting..." << endl;
                        exitStatus = 1;
                    }
                }
                else 
                {
                    throw;
                }
            }
        } while(retry);
    }
    catch (const exception& e)
    {
        cout << "Failed with error: " << e.what() << "\n";
        exitStatus = 1;
    }
    
    // Should be called to free resources allocated in AcmeClient::init
    acme_lw::AcmeClient::teardown();
    
    return exitStatus;
}

namespace
{

string readFile(const string& fileName)
{
    ifstream f(fileName);
    if (f.fail())
    {
        cout << "Unable to open " << fileName << "\n";
        exit(1);
    }

    stringstream ss;
    ss << f.rdbuf();
    f.close();
    if (f.fail())
    {
        cout << "Failure reading " << fileName << "\n";
        exit(1);
    }

    return ss.str();
}

// Doesn't worry about permissions
void rawWriteFile(const string& fileName, const string& contents)
{
    ofstream f(fileName);
    if (f.fail())
    {
        cout << "Unable to write " << fileName << "\n";
        exit(1);
    }
    f.write(contents.c_str(), contents.size());
    f.close();
    if (f.fail())
    {
        cout << "Unable to write " << fileName << "\n";
        exit(1);
    }
}

// Write files with read / write permissions only to the current user.
void writeFile(const string& fileName, const string& contents)
{
    if (::remove(fileName.c_str()) && errno != ENOENT)
    {
        cout << errno << " Unable to remove " << fileName << "\n";
        exit(1);
    }

    rawWriteFile(fileName, "");
    fs::permissions(fileName, fs::perms::owner_read | fs::perms::owner_write);
    rawWriteFile(fileName, contents);
}

}
